# netredact

netredact removes or substitutes sensitive material in network-device configuration while preserving the structure needed for its intended audience.

## Language

**Selector**:
A named kind of sensitive material that policy can act on, identified by its value, its location in network configuration, or both.
_Avoid_: Detector, matcher

**Replace**:
Writing sanitised output back over the input file, destroying the original. The CLI spells it `-r` / `--replace`.
_Avoid_: In-place, overwrite (kept only as ordinary English, never as the name of the operation)

**Provenance marker**:
The single comment line netredact writes at the top of a file it produced, naming the tool and its version. It is what makes a file identifiable as output rather than configuration, and so the evidence a second run is refused on.
_Avoid_: Header, banner (a banner is device configuration that netredact acts on)

**Walk**:
Expanding a directory argument into the files netredact will read. A walk chooses its own files, so it may decline one; a path named on the command line is always attempted.
_Avoid_: Scan, crawl

