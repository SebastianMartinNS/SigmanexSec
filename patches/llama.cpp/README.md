# `llama.cpp` patches

This directory holds the nine local patches that SAP-Pentest applies on
top of upstream `ggerganov/llama.cpp`. The full rationale for every
patch is in [`../../LLAMACPP_FORK.md`](../../LLAMACPP_FORK.md).

The companion `llama.cpp/` directory in this repository is a **git
submodule** pinned to the commit recorded in [`PINNED.txt`](PINNED.txt).
The submodule itself stays at upstream; the patches are applied on top
by [`scripts/apply_llamacpp_patches.sh`](../../scripts/apply_llamacpp_patches.sh).

## How to bring up a fresh checkout

```bash
git clone https://github.com/SebastianMartinNS/SigmanexSec.git
cd SigmanexSec
git submodule update --init --recursive
bash scripts/apply_llamacpp_patches.sh
```

After that, follow the build steps in
[`../../LLAMACPP_FORK.md`](../../LLAMACPP_FORK.md) to rebuild the
WebUI bundle and `llama-server`.

## How to refresh the patches against a newer upstream

```bash
# 1. Update the submodule
cd llama.cpp
git fetch origin
git checkout <new-commit>
cd ..

# 2. Re-apply the patches and resolve any conflicts manually
bash scripts/apply_llamacpp_patches.sh   # will surface conflicts

# 3. Once the working tree is clean and tested, regenerate the patches
for f in $(git -C llama.cpp diff --name-only); do
  safe=$(echo "$f" | tr '/' '_')
  git -C llama.cpp diff "$f" > patches/llama.cpp/${safe}.patch
done

# 4. Update PINNED.txt and commit
```
