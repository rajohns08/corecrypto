# Copyright (c) (2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

import pdb
from rng import *
import argparse
import sys
import hashlib
import random
from enum import Enum
from copy import deepcopy
from codegen import *
from os import urandom
from random import choice
from sys import float_info


class TestGenerator(CodeGenerator):
    def __init__(self):
        super().__init__()
        self.errkinds = list(RNGError.Kind)
        self.tid = 0
        self.vecs = []

    def gentid(self):
        self.tid += 1
        return self.tid

    def genop_init(self, max_ngens, entropybuf_nbytes, seed, nonce, prng):
        seed_sym = self.gendecl('uint8_t {}[]', 'seed', seed)
        nonce_sym = self.gendecl('uint8_t {}[]', 'nonce', nonce)
        return self.gendecl('struct kprng_op_init {}', 'op_init', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_INIT'),
            },
            'max_ngens': max_ngens,
            'entropybuf_nbytes': entropybuf_nbytes,
            'seed_nbytes': sizeof(seed_sym),
            'seed': seed_sym,
            'nonce_nbytes': sizeof(nonce_sym),
            'nonce': nonce_sym,
            'out': {
                'key': prng.key
            }
        })

    def genop_initgen(self, genid, prng):
        return self.gendecl('struct kprng_op_initgen {}', 'op_initgen', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_INITGEN'),
            },
            'gen_idx': genid,
            'out': {
                'key': prng.gens[genid].key,
                'ctr': prng.gens[genid].ctr
            }
        })

    def genop_initgen_abort(self, genid):
        return self.gendecl('struct kprng_op_initgen {}', 'op_initgen', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_INITGEN'),
                'abort': True
            },
            'gen_idx': genid
        })

    # Heh.
    def gengens(self, prng):
        gen_syms = []
        for genid, g in enumerate(prng.gens):
            if not g.init:
                continue
            gen_sym = self.gendecl('struct kprng_gen {}', 'gen', {
                'gen_idx': genid,
                'key': g.key,
            })
            gen_syms.append(gen_sym)
        return self.gendecl('struct kprng_gen *{}[]', 'gens', [ref(s) for s in gen_syms])

    def genop_reseed(self, seed, prng):
        seed_sym = self.gendecl('uint8_t {}[]', 'seed', seed)
        gens_sym = self.gengens(prng)
        return self.gendecl('struct kprng_op_reseed {}', 'op_reseed', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_RESEED')
            },
            'seed_nbytes': sizeof(seed_sym),
            'seed': seed_sym,
            'out': {
                'key': prng.key,
                'ngens': len([gen for gen in prng.gens if gen.init == True]),
                'gens': gens_sym
            }
        })

    def genop_refresh(self, entropy, nsamples, nsamples_last, reseed, rand, prng):
        pool_idx_prev = (prng.pool_i - 1) % prng._NPOOLS
        pool = prng.pools[pool_idx_prev]
        gens_sym = self.gengens(prng)
        return self.gendecl('struct kprng_op_refresh {}', 'op_refresh', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_REFRESH')
            },
            'entropybuf': entropy,
            'entropybuf_nsamples': nsamples,
            'rand': uint64(rand),
            'out': {
                'reseed': reseed,
                'sched': prng.schedule,
                'entropybuf_nsamples_last': nsamples_last,
                'key': prng.key,
                'ngens': len([gen for gen in prng.gens if gen.init == True]),
                'gens': gens_sym,
                'pool_idx': prng.pool_i,
                'pools': [dict(data=p.data, nsamples=d.nsamples) for p, d in zip(prng.pools, prng.diag.pools)]
            }
        })

    def genop_addentropy(self, entropy, nsamples, prng, rand):
        entropy_sym = self.gendecl('uint8_t {}[]', 'entropy', entropy)
        pool_idx_prev = (prng.pool_i - 1) % prng._NPOOLS
        pool = prng.pools[pool_idx_prev]
        return self.gendecl('struct kprng_op_addentropy {}', 'op_addentropy', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_ADDENTROPY')
            },
            'entropy_nbytes': sizeof(entropy_sym),
            'entropy': entropy_sym,
            'nsamples': nsamples,
            'rand': uint64(rand),
            'out': {
                'pool_idx': prng.pool_i,
                'pool': {
                    'data': pool.data,
                    'nsamples': prng.diag.pools[pool_idx_prev].nsamples
                }
            }
        })

    def genop_generate(self, genid, rand, prng):
        return self.gendecl('struct kprng_op_generate {}', 'op_generate', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_GENERATE')
            },
            'gen_idx': genid,
            'rand_nbytes': len(rand),
            'out': {
                'rand': rand,
                'key': prng.gens[genid].key,
                'ctr': prng.gens[genid].ctr
            }
        })

    def genop_generate_abort(self, genid, rand_nbytes):
        return self.gendecl('struct kprng_op_generate {}', 'op_generate', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_GENERATE'),
                'abort': True
            },
            'gen_idx': genid,
            'rand_nbytes': rand_nbytes
        })

    def genvector(self, name, note, ops, diag):
        ops_sym = self.gendecl('struct kprng_op *{}[]', 'ops', [('const struct kprng_op *', ref(op)) for op in ops])
        gendiags_sym = self.gendecl('struct cckprng_gen_diag {}[]', 'gen_diags', [
            {
                'nrekeys': g.nrekeys,
                'out_nreqs': g.out_nreqs,
                'out_nbytes': g.out_nbytes,
                'out_nbytes_req_max': g.out_nbytes_req_max,
                'out_nbytes_key': g.out_nbytes_key,
                'out_nbytes_key_max': g.out_nbytes_key_max,
            }
            for g in diag.gens
        ], const=False)
        return self.gendecl('struct kprng_vector {}', name, {
            'id': self.gentid(),
            'note': note,
            'nops': len(ops),
            'ops': ops_sym,
            'diag': {
                'userreseed_nreseeds': diag.userreseed_nreseeds,
                'schedreseed_nreseeds': diag.schedreseed_nreseeds,
                'schedreseed_nsamples_max': diag.schedreseed_nsamples_max,
                'addentropy_nsamples_max': diag.addentropy_nsamples_max,
                'pools': [
                    {
                        'nsamples': p.nsamples,
                        'ndrains': p.ndrains,
                        'nsamples_max': p.nsamples_max
                    }
                    for p in diag.pools
                ],
                'ngens': len(diag.gens),
                'gens': gendiags_sym
            }
        })

    def gentest(self, nops):
        seed = urandom(32)
        nonce = urandom(8)
        max_ngens = choice(range(1, 65))
        entropybuf_nbytes = choice(range(1, 65))
        entropybuf = EntropyBuffer(entropybuf_nbytes)
        prng = RNG(max_ngens, entropybuf, seed, nonce)
        ops = [self.genop_init(max_ngens, entropybuf_nbytes, seed, nonce, prng)]
        kinds = ['INITGEN', 'RESEED', 'REFRESH', 'GENERATE']
        note = None

        while len(ops) < nops:
            prngcopy = deepcopy(prng)
            kind = choice(kinds)

            try:
                if kind == 'INITGEN':
                    genid = choice(range(max_ngens + 2))
                    prng.initialize_generator(genid)
                    ops.append(self.genop_initgen(genid, prng))
                elif kind == 'RESEED':
                    seed = urandom(choice(range(256)))
                    prng.reseed(seed)
                    ops.append(self.genop_reseed(seed, prng))
                elif kind == 'REFRESH':
                    prng.entropybuf.buf[:] = urandom(entropybuf_nbytes)
                    prng.entropybuf.nsamples += ord(urandom(1))
                    reseed, rand = prng.refresh()
                    ops.append(self.genop_refresh(prng.entropybuf.buf, prng.entropybuf.nsamples, prng.entropybuf_nsamples_last, reseed, rand, prng))
                elif kind == 'GENERATE':
                    genid = choice(range(max_ngens + 2))
                    rand_nbytes = choice(range(288))
                    rand = prng.generate(genid, rand_nbytes)
                    ops.append(self.genop_generate(genid, rand, prng))

            except RNGError as err:
                if err.kind not in self.errkinds:
                    prng = prngcopy
                    continue

                self.errkinds.remove(err.kind)

                if err.kind in [RNGError.Kind.initgen_range, RNGError.Kind.initgen_init]:
                    ops.append(self.genop_initgen_abort(genid))
                elif err.kind in [RNGError.Kind.generate_range, RNGError.Kind.generate_init, RNGError.Kind.generate_reqsize]:
                    ops.append(self.genop_generate_abort(genid, rand_nbytes))

                note = err.note
                break

        vec = self.genvector('vec', note, ops, prng.diag)
        self.vecs.append(vec)
        return vec

    def finalize(self):
        return self.gendecl('struct kprng_vector *{}[]', symbol('test_vectors'), [ref(v) for v in self.vecs])


def gentests(outfile):
    testgen = TestGenerator()
    for _ in range(256):
        print('generating test', len(testgen.vecs))
        testgen.gentest(16)
    for _ in range(2):
        print('generating test', len(testgen.vecs))
        testgen.gentest(1024)
    testgen.finalize()
    with open(outfile, 'w') as f:
        f.write('\n\n'.join(testgen.decls))
        f.write('\n')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", help = "'generate' or 'run' test cases")
    parser.add_argument("-o", "--output", help = "C output file")
    args = parser.parse_args()

    if args.command not in ["generate"]:
        print("Invalid command: %s! Must be 'generate' or 'run'" % args.command)
        sys.exit(-1)
    elif args.command == "generate":
        gentests(args.output)
