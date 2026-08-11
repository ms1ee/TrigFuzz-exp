# trigfuzz-exp

## 1. Obtain TCUs

```sh
export OPENAI_BASE_URL="https://api.anthropic.com/v1/chat/completions"
export OPENAI_MODEL="claude-opus-4-6"
export OPENAI_API_KEY="..."
export REPO="$PWD"
export PYTHONPATH="$REPO/trigfuzz"

python3 -B -m trigfuzz.tcgen work/cxxfilt-2016-4489 \
    --source libiberty/cplus-dem.c --k 1 --out work/cxxfilt-2016-4489/tcus.json
```

## 2. Build binary

```sh
cd work/cxxfilt-2016-4489/source
export PYTHONPATH="$REPO/trigfuzz"

python3 -B -m trigfuzz.instrument . ../tcus.json --meta-out ../cxxfilt-2016-4489.meta

AFL_DIR="$REPO/trigfuzz/engines/aflgo-trigfuzz/afl-2.57b"
export AFL_PATH="$AFL_DIR"
CC="$AFL_DIR/afl-gcc" CXX="$AFL_DIR/afl-g++" CFLAGS="-g -fno-omit-frame-pointer -Wno-error" \
    CXXFLAGS="-g -fno-omit-frame-pointer -Wno-error" \
    ./configure --disable-shared --disable-gdb --disable-libdecnumber \
    --disable-readline --disable-sim --disable-ld && make
```

## 3. Fuzz binary

```sh
cd work/cxxfilt-2016-4489/source
source ../cxxfilt-2016-4489.meta   # INS_NUM / SEQ_NUM
export AFL_TRIG_ENABLE_BYTE_AWARE_MUTATION=1
export AFL_TRIG_MUTATION_MODE=diff
timeout 86400 $REPO/trigfuzz/engines/aflgo-trigfuzz/afl-2.57b/afl-fuzz \
    -m none -d -z exp -c 10m -a $INS_NUM -s $SEQ_NUM \
    -i $REPO/seed -o output -- ./binutils/cxxfilt
```
