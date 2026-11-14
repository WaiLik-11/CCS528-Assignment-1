"""Benchmark figure shared by the PQC tasks: operation times next to object sizes."""

from pathlib import Path

COLORS = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100")
INK, MUTED_INK, GRID = "#0b0b0b", "#52514e", "#e4e3df"


def plot_time_and_size(
    rows: list[dict],
    operations: tuple[str, ...],
    operation_labels: tuple[str, ...],
    size_keys: tuple[str, ...],
    size_labels: tuple[str, ...],
    title: str,
    path: Path,
    log_scale: bool = False,
) -> Path:
    """Two grouped bar charts per parameter set: mean time (µs, ±1 std) and sizes (bytes).

    Each row needs `parameter_set`, `<op>_mean_ms`, `<op>_std_ms` for every operation, and every size key.
    log_scale uses a log y-axis on both panels, useful when classical and PQC values span orders of magnitude.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    names = [r["parameter_set"] for r in rows]
    x = np.arange(len(names))
    width = 0.26

    fig, (ax_t, ax_s) = plt.subplots(1, 2, figsize=(12, 4.6))
    panels = (
        (
            ax_t,
            operations,
            operation_labels,
            lambda r, op: r[f"{op}_mean_ms"] * 1000,
            lambda r, op: r[f"{op}_std_ms"] * 1000,
            "Mean time (µs), error bar = 1 std dev",
            "Operation time",
        ),
        (
            ax_s,
            size_keys,
            size_labels,
            lambda r, k: r[k],
            None,
            "Size (bytes)",
            "Key and " + size_labels[-1].lower() + " size",
        ),
    )
    for ax, keys, labels, value, err, ylabel, panel_title in panels:
        for i, (key, label) in enumerate(zip(keys, labels)):
            vals = [value(r, key) for r in rows]
            errs = [err(r, key) for r in rows] if err else None
            bars = ax.bar(
                x + (i - 1) * width,
                vals,
                width - 0.02,
                yerr=errs,
                label=label,
                color=COLORS[i],
                edgecolor="white",
                linewidth=2,
                error_kw={"ecolor": "#52514e", "elinewidth": 1, "capsize": 3},
            )
            if err is None:
                ax.bar_label(bars, fmt="%d", fontsize=8, color="#52514e", padding=2)
        ax.set_xticks(x, names)
        ax.set_ylabel(ylabel, color="#52514e")
        ax.set_title(panel_title, loc="left", fontsize=12, color="#0b0b0b")
        ax.legend(frameon=False)
        ax.grid(axis="y", color="#e4e3df", linewidth=0.8)
        ax.set_axisbelow(True)
        if log_scale:
            ax.set_yscale("log")
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        ax.tick_params(colors="#52514e")

    fig.suptitle(title, x=0.01, ha="left", fontsize=13)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=200)
    plt.close(fig)
    return path
