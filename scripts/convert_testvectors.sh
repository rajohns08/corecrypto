# Copyright (c) (2018-2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#!/bin/bash

OUTFILE=$1
INPUT_DIR=$2
INPUT_DIRS=()
INPUT_FNAMES=()
OUTPUT_FNAMES=()

NAMES=()
STRUCTURES=()
LENGTHS=()

# Concatenate each struct to a single file
echo "#ifndef test_vectors_h" > ${OUTFILE}
echo "#define test_vectors_h" >> ${OUTFILE}
echo "" >> ${OUTFILE}

for FNAME in $(find ${INPUT_DIR} -name *.json)
do
    xxd --include ${FNAME} > ${FNAME}.c
    OUTPUT_FNAMES+=(${FNAME}.c)

    PARSER=$(basename $(dirname ${FNAME}))
    STRUCTNAME=`grep "unsigned char" ${FNAME}.c | sed -e 's/unsigned\ char\ \(.*\)\[\]\ \=\ \(.*\)/\1/'`
    LENGTH=`grep "unsigned int" ${FNAME}.c | sed -e 's/unsigned\ int\ \(.*\)\ \=\ \(.*\)/\1/'`
    NAME=`basename -s ".json" ${FNAME}`

    sed -e "s/${STRUCTNAME}/${NAME}/g" ${FNAME}.c > ${FNAME}.c.tmp && mv ${FNAME}.c.tmp ${FNAME}.c
    sed -e "s/unsigned\ int\ ${NAME}/const\ unsigned\ int\ ${NAME}_len/g" ${FNAME}.c > ${FNAME}.c.tmp && mv ${FNAME}.c.tmp ${FNAME}.c
    LENGTH=`grep "unsigned int" ${FNAME}.c | sed -e 's/const\ unsigned\ int\ \(.*\)\ \=\ \(.*\)/\1/'`

    NAMES+=(${PARSER})
    STRUCTURES+=(${NAME})
    LENGTHS+=(${LENGTH})
done

for i in "${!OUTPUT_FNAMES[@]}"
do
    FNAME=${OUTPUT_FNAMES[$i]}
    cat ${FNAME} >> ${OUTFILE}
    rm ${FNAME}
done

echo "" >> ${OUTFILE}
echo "struct ccgenerated_test_vector {" >> ${OUTFILE}
echo "    const char *parser;" >> ${OUTFILE}
echo "    const uint8_t *buffer;" >> ${OUTFILE}
echo "    size_t buffer_len;" >> ${OUTFILE}
echo "};" >> ${OUTFILE}

echo "" >> ${OUTFILE}
echo "const struct ccgenerated_test_vector ccgenerated_test_vectors[] = {" >> ${OUTFILE}
for i in "${!OUTPUT_FNAMES[@]}"
do
    STRUCTNAME=${STRUCTURES[$i]}
    LENGTH=${LENGTHS[$i]}
    PARSER=${NAMES[$i]}
    echo "    { .parser = \"${PARSER}\", .buffer = ${STRUCTNAME}, .buffer_len = ${LENGTH} }," >> ${OUTFILE}
done
echo "};" >> ${OUTFILE}

echo "" >> ${OUTFILE}
echo "const size_t ccgenerated_test_vectors_count = ${#OUTPUT_FNAMES[@]};" >> ${OUTFILE}
echo "" >> ${OUTFILE}

echo "#endif" >> ${OUTFILE}
