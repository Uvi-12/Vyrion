"""python -m vyrion._harness.cli --out reports [--project PATH]"""
import argparse
from .runner import run_fleet


def main():
    ap = argparse.ArgumentParser(description="Vyrion HITL Attack-Surface Harness")
    ap.add_argument("--out", default="reports", help="output directory")
    ap.add_argument("--project", default=None,
                    help="target project path (default: bundled samples)")
    args = ap.parse_args()
    index = run_fleet(out_dir=args.out, project_override=args.project)
    t = index["totals"]
    print(f"analyzed {len(index['frameworks'])} frameworks | detected {t['detected']} | "
          f"chains {t['with_chain']} | surface points {t['applicable_points']}")


if __name__ == "__main__":
    main()
