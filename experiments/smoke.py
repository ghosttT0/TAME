"""No-LLM smoke test: runs the full pipeline with MockClient on a tiny dataset."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loginject.dataset import build_dataset
from loginject.harness import Harness, parse_verdict
from loginject.llm import MockClient
from loginject.eval import eval_sequence, aggregate, aggregate_by


def main():
    ds = build_dataset(2)
    client = MockClient()
    rows = []
    for mode in ("S0", "S1", "S2", "S3", "S4"):
        for s in ds:
            run = Harness(mode, client).run(s)
            row = eval_sequence(run)
            rows.append(row)
            print(f"{s.sid} {mode} W:{[row[f'w{i}_verdict'] for i in (1,2,3,4)]} "
                  f"IASR={row['IASR']} DASR={row['DASR']} CPL={row['CPL']}")
    print()
    print("by mode:")
    for k, v in aggregate_by(rows, "mode").items():
        print(f"  {k}: IASR={v['IASR']:.2f} DASR={v['DASR']:.2f} CPL={v['CPL_mean']:.2f} "
              f"BMR={v['BMR']:.2f} MTR={v['MTR']:.2f} "
              f"sumC={v['summary_contamination']:.2f} noteC={v['note_contamination']:.2f}")
    assert parse_verdict('{"verdict": "malicious", "reason": "x"}')["verdict"] == "malicious"
    print("smoke OK")


if __name__ == "__main__":
    main()