# Copyright (c) (2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

import enum
import struct
import hashlib
import inspect
import random
from functools import wraps
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

dec64 = lambda s: struct.unpack('>Q', s)[0]
enc64 = lambda i: struct.pack('>Q', i)

dec32 = lambda s: struct.unpack('>L', s)[0]
enc32 = lambda i: struct.pack('>L', i)

# least significant set bit of x (indexed from one)
def ffs(x):
    assert x > 0
    i = 1
    while x & 1 == 0:
        i += 1
        x >>= 1
    return i

def enforce_byte_args(f):
    @wraps(f)
    def wrapper(*args, **kwds):
        for i, (param_name, param_input) in enumerate(zip(inspect.signature(f).parameters.keys(), args)):
            if param_name.endswith("_b"):
                if not type(param_input) is bytes:
                    raise Exception("Arg %d is of type %s, not bytes!" % (i, type(param_input)))
        return f(*args, **kwds)
    return wrapper

@enforce_byte_args
def F(ctx, outlen):
    cipher = Cipher(algorithms.AES(ctx.key), modes.CTR(ctx.ctr), backend=default_backend())
    encryptor = cipher.encryptor()
    ctx.key = encryptor.update(b"\x00" * len(ctx.key))
    new_ctr = dec64(ctx.ctr[4:12]) + 1
    ctx.ctr = b"%b%b%b" % (ctx.ctr[:4], enc64(new_ctr), bytes(4))
    return encryptor.update(b"\x00" * outlen) + encryptor.finalize()

_NPOOLS = 32
_NGENS  = 64

_REFRESH_MIN_NSAMPLES = 32

class Diagnostics(object):
    def __init__(self, ngens):
        self.userreseed_nreseeds = 0
        self.schedreseed_nreseeds = 0
        self.schedreseed_nsamples_max = 0
        self.addentropy_nsamples_max = 0
        self.pools = [PoolDiagnostics() for _ in range(_NPOOLS)]
        self.gens = [GeneratorDiagnostics() for _ in range(ngens)]


class GeneratorDiagnostics(object):
    def __init__(self):
        self.nrekeys = 0
        self.out_nreqs = 0
        self.out_nbytes = 0
        self.out_nbytes_req_max = 0
        self.out_nbytes_key = 0
        self.out_nbytes_key_max = 0

        self.clear_out_nbytes_key = False

class PoolDiagnostics(object):
    def __init__(self):
        self.nsamples = 0
        self.ndrains = 0
        self.nsamples_max = 0


class Generator(object):
    pass

class Pool(object):
    pass

class EntropyBuffer(object):
    def __init__(self, nbytes):
        self.buf = bytearray(nbytes)
        self.nsamples = 0

class RNGError(Exception):
    class Kind(enum.IntEnum):
        initgen_range = 1
        initgen_init = 2
        generate_range = 3
        generate_init = 4
        generate_reqsize = 5

    def __init__(self, kind, note):
        self.kind = kind
        self.note = note

class RNG(object):
    _PRNG_NAME    = b"xnuprng"
    _INIT         = _PRNG_NAME + b"\x00"
    _USER_RESEED  = _PRNG_NAME + b"\x01"
    _SCHED_RESEED = _PRNG_NAME + b"\x02"
    _ADD_ENTROPY  = _PRNG_NAME + b"\x03"

    _NPOOLS = _NPOOLS
    _NGENS  = _NGENS

    @enforce_byte_args
    def _hash(ctx, personalization_str_b, data_b):
        assert(ctx.H)
        to_hash = b"%b%b" % (personalization_str_b, data_b)
        hasher = ctx.H()
        hasher.update(to_hash)
        return hasher.digest()

    @enforce_byte_args
    def __init__(ctx, max_ngens, entropybuf, seed_b, nonce_b, H=hashlib.sha256, F=F):
        ctx.H = H
        ctx.F = F
        ctx.key = ctx._hash(
            ctx._INIT,
            b"%b%b%b%b" % (enc64(len(nonce_b)), nonce_b, enc64(len(seed_b)), seed_b)
        )
        ctx.ctr = b"%b%b" % (enc32(0xffffffff), bytes(12))
        ctx.entropybuf = entropybuf
        ctx.entropybuf_nsamples_last = 0
        ctx.max_ngens = max_ngens
        ctx.ngens = 0
        ctx.gens = []
        ctx.pools = []
        for i in range(0, ctx._NPOOLS):
            pool = Pool()
            pool.data = bytes(32)
            ctx.pools.append(pool)

        for i in range(0, ctx.max_ngens):
            generator = Generator()
            generator.init = False
            generator.key = bytes(32)
            generator.ctr = bytes(16)
            ctx.gens.append(generator)

        ctx.schedule = 0
        ctx.reseed_last = 0
        ctx.reseed_ready = False
        ctx.pool_i = 0

        ctx.diag = Diagnostics(max_ngens)

    def initialize_generator(ctx, i):
        if i >= ctx.max_ngens:
            raise RNGError(RNGError.Kind.initgen_range, 'initgen: genid out of range')

        generator = ctx.gens[i]
        if generator.init:
            raise RNGError(RNGError.Kind.initgen_init, 'initgen: genid already init')

        generator.ctr = b"%b%b" % (enc32(i), generator.ctr[4:])
        generator.key = ctx.F(ctx, 32)

        generator.init = True
        ctx.ngens += 1
        ctx.diag.gens[i].nrekeys = 1
        return True

    def _rekey_generators(ctx):
        keys = ctx.F(ctx, 32 * ctx.ngens)

        for i in range(0, ctx.max_ngens):
            generator = ctx.gens[i]
            if not generator.init:
                continue
            generator.key = keys[:32]
            keys = keys[32:]
            gen_diag = ctx.diag.gens[i]
            gen_diag.nrekeys += 1
            gen_diag.clear_out_nbytes_key = True

    def _schedule(ctx):
        pool_in = -1
        if ctx.entropybuf.nsamples - ctx.entropybuf_nsamples_last >= _REFRESH_MIN_NSAMPLES:
            pool_in = ctx.pool_i
            ctx.pool_i = (ctx.pool_i + 1) % ctx._NPOOLS

        pool_out = -1
        if pool_in == 0:
            ctx.schedule += 1
            pool_out = ffs(ctx.schedule)

        return pool_in, pool_out

    def _addentropy(ctx, pool_i, rdrand):
        if pool_i == -1:
            return 0

        pool = ctx.pools[pool_i]
        pool.data = ctx._hash(
            ctx._ADD_ENTROPY,
            b"%b%b%b%b" % (enc32(pool_i), pool.data, enc64(rdrand), ctx.entropybuf.buf)
        )

        nsamples = ctx.entropybuf.nsamples - ctx.entropybuf_nsamples_last
        ctx.entropybuf_nsamples_last = ctx.entropybuf.nsamples
        pool_diag = ctx.diag.pools[pool_i]
        pool_diag.nsamples += nsamples
        pool_diag.nsamples_max = max(pool_diag.nsamples_max, pool_diag.nsamples)
        ctx.diag.addentropy_nsamples_max = max(ctx.diag.addentropy_nsamples_max, nsamples)

        return rdrand

    def _schedreseed(ctx, pool_i):
        if pool_i == -1:
            return

        h = ctx.H()
        h.update(b"%b%b%b" % (ctx._SCHED_RESEED, enc64(ctx.schedule), ctx.key))

        i = 0
        nsamples = 0
        while i < pool_i:
            pool = ctx.pools[i]
            h.update(pool.data)
            pool.data = bytes(32)
            pool_diag = ctx.diag.pools[i]
            nsamples += pool_diag.nsamples
            pool_diag.nsamples = 0
            pool_diag.ndrains += 1
            i += 1

        ctx.key = h.digest()
        ctx._rekey_generators()
        ctx.diag.schedreseed_nreseeds += 1
        ctx.diag.schedreseed_nsamples_max = max(ctx.diag.schedreseed_nsamples_max, nsamples)
        ctx.reseed_ready = False

    def refresh(ctx):
        pool_in, pool_out = ctx._schedule()
        rdrand = random.randint(0, (1 << 64) - 1)
        ctx._addentropy(pool_in, rdrand)
        ctx._schedreseed(pool_out)

        return (pool_out != -1), rdrand

    def reseed(ctx, seed_b):
        ctx.key = ctx._hash(
            ctx._USER_RESEED,
            b"%b%b" % (ctx.key, seed_b)
        )
        ctx._rekey_generators()
        ctx.diag.userreseed_nreseeds += 1

    def scheduler_reseed(ctx):
        if ctx.reseed_ready:
            ctx.schedule += 1

            h = ctx.H()
            h.update(b"%b%b%b" % (ctx._SCHED_RESEED, enc64(ctx.schedule), ctx.key))

            i = 0
            nsamples = 0
            while ctx.schedule % (1 << i) == 0:
                pool = ctx.pools[i]
                h.update(pool.data)
                pool.data = bytes(32)
                pool_diag = ctx.diag.pools[i]
                nsamples += pool_diag.nsamples
                pool_diag.nsamples = 0
                pool_diag.ndrains += 1
                i += 1

            ctx.key = h.digest()
            ctx._rekey_generators()
            ctx.diag.schedreseed_nreseeds += 1
            ctx.diag.schedreseed_nsamples_max = max(ctx.diag.schedreseed_nsamples_max, nsamples)
            ctx.reseed_ready = False
            return True
        else:
            return False

    def generate(ctx, i, outlen):
        if i >= ctx.max_ngens:
            raise RNGError(RNGError.Kind.generate_range, 'generate: genid out of range')
        if outlen > 256:
            raise RNGError(RNGError.Kind.generate_reqsize, 'generate: request size out of range')

        generator = ctx.gens[i]
        if not generator.init:
            raise RNGError(RNGError.Kind.generate_init, 'generate: genid not init')

        # This is a concession to implementation details. Although it
        # would be more natural just to set out_nbytes_key to zero
        # where this flag is set (see _rekey_generators), this is not
        # how the C implementation works due to its support for
        # concurrent generation and reseeds.
        gen_diag = ctx.diag.gens[i]
        if gen_diag.clear_out_nbytes_key:
            gen_diag.clear_out_nbytes_key = False
            gen_diag.out_nbytes_key = 0

        gen_diag.out_nreqs += 1
        gen_diag.out_nbytes += outlen
        gen_diag.out_nbytes_req_max = max(gen_diag.out_nbytes_req_max, outlen)
        gen_diag.out_nbytes_key += outlen
        gen_diag.out_nbytes_key_max = max(gen_diag.out_nbytes_key_max, gen_diag.out_nbytes_key)

        return ctx.F(generator, outlen)

if __name__ == "__main__":
    entropybuf = EntropyBuffer(32)
    rng = RNG(_NGENS, entropybuf, b"Green Chartruese", b"Yellow Chartruese")
    for x in range(0, int(rng._NPOOLS / 2)):
        rng.initialize_generator(x)

    try:
        rng.initialize_generator(0)
    except RNGError as e:
        assert e.kind is RNGError.Kind.initgen_init, "Initializing same generator expects initgen_range error"
    except Exception as e:
        assert 1 == 2, "Initializing same generator expects initgen_range error"

    try:
        rng.initialize_generator(rng._NPOOLS + 1)
    except RNGError as e:
        assert e.kind is RNGError.Kind.initgen_range, "Initializing same generator expects initgen_range error"
    except Exception as e:
        assert 1 == 2, "Initializing same generator expects initgen_range error"

    rng.reseed(b"User reseed1")
    assert rng.gens[-1].key == bytes(32), "Rekey modified an uninitialized generator's key !"

    did_reseed = rng.refresh()[0]
    assert did_reseed is False, "We haven't added any entropy yet"

    did_reseed = rng.refresh(b"entropy1", 1)[0]
    assert did_reseed is True, "We should have reseeded !"

    try:
        output = rng.generate(65, 42)
    except RNGError as e:
        assert e.kind is RNGError.Kind.generate_range, "Expecting a generate_range error"

    try:
        output = rng.generate(1, 420)
    except RNGError as e:
        assert e.kind is RNGError.Kind.generate_reqsize, "Expecting a generate_reqsize error"

    try:
        output = rng.generate(rng.max_ngens - 1, 42)
    except RNGError as e:
        assert e.kind is RNGError.Kind.generate_init, "Expecting a generate_init error"

    output1 = rng.generate(0, 32)
    assert len(output1) == 32
    output2 = rng.generate(0, 32)
    assert output1 != output2
    output3 = rng.generate(1, 32)
    assert output2 != output3
