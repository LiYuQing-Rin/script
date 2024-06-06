import os
from glob import glob
from typing import List
from datetime import datetime
from multiprocessing import Pool

import pandas as pd
from sysdig import Sysdig

def get_scap_paths(scap_dir: str) -> List[str]:
    """Get all paths to .scap files
    """
    paths = glob(os.path.join(scap_dir, "**", "*.scap"), recursive=True)
    return paths

def get_scap_dfs(scap_paths: List[str]) -> pd.DataFrame:
    """Load .scap files and convert to DataFrame
    """
    pool = Pool()
    scap_dfs = None
    final_dfs = []

    with Pool() as pool:
        async_result = pool.map_async(Sysdig().process_scap, scap_paths, chunksize=50)
        pool.close()
        pool.join()
        scap_dfs = async_result.get()

    for scap_path, scap_df in zip(scap_paths, scap_dfs):
        if all(item in scap_df.columns for item in ['timestamp', 'syscall', 'args']):
            label = os.path.basename(os.path.dirname(scap_path))
            today = datetime.now().strftime('%Y-%m-%d')
            scap_df["label"] = label if label != "NORMAL" else "-"
            scap_df["content"] = scap_df["syscall"]
            scap_df["timestamp"] = pd.to_datetime(today + " " + scap_df["timestamp"], format="ISO8601")
            scap_df["timestamp"] = (scap_df["timestamp"] - pd.Timestamp("1970-01-01")) // pd.Timedelta("1s")
            final_dfs.append(scap_df)
        else:
            print(f"Warning: incomplete DataFrame {scap_path}")

    final_df = pd.concat(final_dfs)
    final_df.reset_index(drop=True, inplace=True)
    return final_df

columns={
    "timestamp": "Timestamp", 
    "syscall": "EventTemplate",
    "content": "Content",
    "label": "Label",
    "content": "Content",
    "args": "ParameterList"
}

if __name__ == "main":
    CURRENT_DIR = os.path.dirname(__file__)
    DATASET_DIR = os.path.join(CURRENT_DIR, "/data1/visitor/ContainerHIDS/datasets/CB-DS", "CB-DS")
    NORMAL_SCAP_DIR = os.path.join(DATASET_DIR, "NORMAL")
    ATTACKS_SCAP_DIR = os.path.join(DATASET_DIR, "ATTACKS")
    ATTACKS = [["CVE-2016-9962", "CVE-2019-5736", "CVE-2022-0492", "M_SOCKET", "M_UHELPER", "M-MKNOD", "M-NET", "M-SYS_ADMIN", "M-SYS_MOD"]]
    SCAP_PER_ATTACK = 1

    normal_scap_paths = [os.path.join(NORMAL_SCAP_DIR, f"{x+1}.scap") for x in range(100)]
    attack_scap_paths = [os.path.join(ATTACKS_SCAP_DIR, attack, f"{x+1}.scap") for x in range(SCAP_PER_ATTACK) for attack in ATTACKS]

    log_structured = get_scap_dfs(normal_scap_paths + attack_scap_paths)
    log_structured.rename_axis("LineId", inplace=True)
    log_structured.rename(columns=columns, inplace=True)

    log_structured["EventId"] = log_structured.groupby("EventTemplate").ngroup()
    log_structured = log_structured[["Label", "Timestamp", "Content", "EventId", "EventTemplate", "ParameterList"]]
    log_structured.to_csv(F"CB-DS.log_structured.csv")
    log_template = log_structured.groupby(["EventId", "EventTemplate"]).size().reset_index(name="Occurrences")
    log_template.to_csv(F"CB-DS.log_templates.csv", index=False)