# trigfuzz-exp

## 1

```sh
export OPENAI_BASE_URL="https://api.anthropic.com/v1/chat/completions"
export OPENAI_MODEL="claude-opus-4-6"
export OPENAI_API_KEY="..."
export PYTHONPATH="$PWD/trigfuzz"

python3 -B -m trigfuzz.tcgen work/cxxfilt-2016-4489 \
    --source libiberty/cplus-dem.c --k 1 --out work/cxxfilt-2016-4489/tcus.json
```

## 2

```sh
cd work/cxxfilt-2016-4489/source
export PYTHONPATH="<repo>/trigfuzz"

python3 -B -m trigfuzz.instrument . ../tcus.json --meta-out ../cxxfilt-2016-4489.meta

CC=afl-gcc CXX=afl-g++ CFLAGS="-g -fno-omit-frame-pointer -Wno-error" \
    CXXFLAGS="-g -fno-omit-frame-pointer -Wno-error" \
    PATH="<repo>/trigfuzz/engines/aflgo-trigfuzz/afl-2.57b:$PATH" \
    ./configure --disable-shared --disable-gdb --disable-libdecnumber \
    --disable-readline --disable-sim --disable-ld && make
```

## 3

```sh
cd work/cxxfilt-2016-4489/source
source ../cxxfilt-2016-4489.meta   # INS_NUM / SEQ_NUM
export AFL_TRIG_ENABLE_BYTE_AWARE_MUTATION=1
export AFL_TRIG_MUTATION_MODE=diff
timeout 86400 <repo>/trigfuzz/engines/aflgo-trigfuzz/afl-2.57b/afl-fuzz \
    -m none -d -z exp -c 10m -a $INS_NUM -s $SEQ_NUM \
    -i <repo>/seed -o output -- ./binutils/cxxfilt
```
