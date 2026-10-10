# ADR 0048: Unix socket inode census ignores unaddressable rows

Status: Accepted

## Context

Frozen run `38029865257` on `4ddaa3f` fail-closed nxr/constrained after
`rtt-100-loss-1` at integrity `line-b-1-upload`. Landing `integrity-10000` raw
observation retained
`owned Unix socket rows: duplicate or zero Unix socket inode` while
`integrity-0` on the same process, line-a/line-b integrity-10000, and the other
three cells PASS. Landing-restart on that cell was clean (`primary_error: null`).
Automatic `class_hint` labeled A-product; triage is Class B harness.

Collector reads `/proc/<pid>/net/unix` (network-namespace view), then retains
only rows whose inode appears on the process as `socket:[N]` with `N > 0`
([ADR 0034](0034-qualify-resource-ownership-and-lifetime.md)). The parser
previously rejected the **entire** table when any namespace row had inode `0`
or a duplicated inode, including sockets that can never match a descriptor
target. Linux commonly lists unbound or tearing-down Unix sockets with inode
`0`. Identical duplicate seq_file rows can appear under concurrent
create/destroy. Neither case is product ownership evidence; failing closed on
them manufactures INVALID under lossy RTT / constrained load. Sleeping longer
cannot make inode `0` addressable.

## Decision

1. `unix_rows` **skips** inode `0` rows. They are not descriptor-addressable and
   MUST NOT appear in retained owned evidence.
2. Identical duplicate rows for one inode are collapsed to a single retained
   line.
3. Conflicting row text for one inode stays fail-closed
   (`conflicting Unix socket inode rows`).
4. Owned filtering, runtime Unix count vs startup inventory, and exclusion of
   unowned paths are unchanged. No production timer, sleep, or admission change.
5. Diagnosis classifies these census phrases as Class B harness.

## Consequences

Namespace noise no longer invalidates a coherent owned Unix census. Genuine
missing owned inodes, conflicting kernel rows, and mismatched startup Unix
counts still fail closed. Historical receipts that already recorded the old
error remain immutable. Single-fault coverage is the unit observation of a
namespace table with inode `0` and identical duplicates around an owned inode.

## References

- [Qualify resource ownership and lifetime](0034-qualify-resource-ownership-and-lifetime.md)
- Frozen cell job: https://github.com/jacek4yang/rust-reality/actions/runs/38029865257/job/114151215385
