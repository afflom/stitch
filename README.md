# Stitch guest corresponding source

This dedicated source-distribution branch preserves the source and license materials for the guest built at Stitch commit `d17aa7f3ffc6944b799ac43f6a5bab04ab3b82ef`. It is not a Stitch product release and does not replace the runtime image on any product branch.

## Download and reconstruct

Download this branch as a ZIP using GitHub's **Code → Download ZIP**, extract it, and run from the extracted directory:

```sh
python3 reassemble.py
```

Alternatively clone this branch without checking out product history. Python 3 and approximately 1 GB of free disk space are sufficient to reconstruct the archive (additional space is needed to extract all sources). No package installation, build, network access, or execution of vendor source is performed by the reassembler.

The script verifies every part's byte count, SHA-256 and Git blob SHA, then verifies the complete archive before atomically saving `stitch-guest-corresponding-source.tar.gz`. It refuses to overwrite an existing output. Use `--output /path/to/archive.tar.gz` to choose a destination. Do not concatenate parts in filesystem ordering or omit the final part. `manifest.json` records the exact ordered parts and final identity.

- Archive: **398,457,213 bytes**
- Archive SHA-256: `fbc04b0c55f8421ca9bcf9e9dbac1952c07a1a2d82fd644ac67e66415b0106bc`
- Included guest image: **8,053,248 bytes**
- Guest SHA-256: `313a6b545290a2b47856b49bfcc4c7577469749b315932ae008d39fe70fc7f07`

## Contents and provenance

The archive includes all reviewed `legal-info` target and host source archives, patches and license texts, original `release-materials`, resolved Linux and BusyBox configurations, origin records and a checked file inventory. Only duplicate download/VCS caches were removed from the original artifact. Source obligations and applicable licenses remain those in the supplied upstream source and license files; this branch does not relicense them.

The guest uses Linux 6.18.7, BusyBox 1.38.0, glibc 2.44 snapshot `34106fee698c83eb0af71d4d0381e66b399be746`, and GCC 15.3 runtime components. Buildroot 2026.08.1 is pinned to `7fdeadb3b9f12f78e5fccca914d7fef47090ab9a`. Its source, which automatic legal-info did not save, is explicitly included at `release-materials/buildroot-source.tar.gz`. The external build tree, configurations, patches, licenses and build instructions accompany the source. The exact candidate needs the host command-line override `rdinit=/init` to run the initramfs wrapper; building another image is not required to retrieve its source.

Original evidence: [GitHub Actions run 42906244489](https://github.com/afflom/stitch/actions/runs/42906244489), artifact `guest-candidate-42906244489-1`, ID `13810385970`.
Original artifact ZIP: 758,474,204 bytes, SHA-256 `91e8c082de05e97e0781e97f5636ae89a7b0095001192b3019ab9ff7054fc714`.
The temporary Actions artifact expires; these repository-backed parts preserve the reviewed compact archive independently. The exact parts are ordinary Git blobs, not Git LFS pointers or external download stubs.

Source availability is separate from runtime qualification and product readiness. This source branch alone claims neither complete product verification nor legal certification. Statements of outstanding publication/qualification in historical bundled evidence describe the time of that evidence, not a new runtime result.
