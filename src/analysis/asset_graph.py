"""
攻击面资产关系图。

把"被动发现的子域名"与"站内多页面监测覆盖"从列表展示升级为力导向关系图：
主域名（根节点，颜色=当前健康度）→ 子域名（叶节点，新发现的高亮标注）
                                  → 站内监测页面（叶节点，被篡改的高亮标注）

态势感知的核心是让人一眼看到"暴露面是什么样的"，而不只是曲线图和表格。
使用 networkx 做力导向布局（spring_layout），坐标交给 UI 层用 Plotly 渲染，
两者解耦，方便未来换用其他布局算法或前端库。
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import networkx as nx

from src.collection import content_monitor, subdomain_discovery
from src.storage import db

_NEW_ASSET_WINDOW_HOURS = 24


def _load_latest_health(db_path: str, target_name: str) -> float:
    df = db.query_df(
        db_path,
        "SELECT score FROM health_scores WHERE target_name=? ORDER BY scored_at DESC LIMIT 1",
        (target_name,),
    )
    return float(df.iloc[0]["score"]) if not df.empty else -1.0


def _load_latest_tls(db_path: str, target_name: str) -> float:
    df = db.query_df(
        db_path,
        "SELECT value FROM raw_metrics WHERE target_name=? AND metric_type='tls_security' "
        "ORDER BY collected_at DESC LIMIT 1",
        (target_name,),
    )
    return float(df.iloc[0]["value"]) if not df.empty and df.iloc[0]["value"] is not None else -1.0


def build_graph(db_path: str, target_name: str) -> Dict[str, Any]:
    """
    构建单个监测目标的攻击面关系图。

    返回：
        {
            "nodes": [{"id","label","type","color","size","hover"}...],
            "edges": [(source_id, target_id), ...],
            "pos":   {node_id: (x, y), ...},
            "empty": bool,   # 无子域名也无站内子页面时为 True
        }
    """
    assets = subdomain_discovery.get_assets(db_path, target_name)
    sub_pages = content_monitor.get_latest_subpage_snapshots(db_path, target_name)

    G = nx.Graph()
    root_id = f"root::{target_name}"

    health = _load_latest_health(db_path, target_name)
    tls = _load_latest_tls(db_path, target_name)
    root_color = _score_to_color(health) if health >= 0 else "#94a3b8"
    G.add_node(root_id, kind="root")

    nodes: List[Dict[str, Any]] = [{
        "id": root_id,
        "label": target_name,
        "type": "root",
        "color": root_color,
        "size": 34,
        "hover": (
            f"{target_name}<br>健康度：{health:.1f}" if health >= 0 else f"{target_name}<br>健康度：暂无数据"
        ) + (f"<br>TLS安全评分：{tls:.1f}" if tls >= 0 else ""),
    }]
    edges: List[tuple] = []

    now = datetime.now(timezone.utc)
    new_cutoff = now - timedelta(hours=_NEW_ASSET_WINDOW_HOURS)

    for a in assets:
        sub_id = f"sub::{a['subdomain']}"
        G.add_node(sub_id, kind="subdomain")
        G.add_edge(root_id, sub_id)

        first_seen = a.get("first_seen", "")
        is_new = False
        try:
            fs_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00")) if first_seen else None
            is_new = fs_dt is not None and fs_dt >= new_cutoff
        except ValueError:
            pass

        nodes.append({
            "id": sub_id,
            "label": a["subdomain"],
            "type": "subdomain_new" if is_new else "subdomain",
            "color": "#bc4c00" if is_new else "#8250df",
            "size": 20 if is_new else 15,
            "hover": (
                f"子域名：{a['subdomain']}<br>来源：{a.get('source','crt.sh')}<br>"
                f"首次发现：{first_seen[:19]}<br>"
                + ("⚠️ 24小时内新发现" if is_new else "已持续跟踪")
            ),
        })
        edges.append((root_id, sub_id))

    for p in sub_pages:
        page_id = f"page::{p['page_path']}"
        G.add_node(page_id, kind="subpage")
        G.add_edge(root_id, page_id)
        changed = bool(p.get("changed"))

        nodes.append({
            "id": page_id,
            "label": p["page_path"] or "/",
            "type": "subpage_changed" if changed else "subpage",
            "color": "#cf222e" if changed else "#1a7f37",
            "size": 20 if changed else 14,
            "hover": (
                f"站内页面：{p['page_path']}<br>"
                + ("🚨 内容发生变化" if changed else "✅ 内容无异常")
                + (f"<br>{p.get('change_summary','')}" if changed and p.get("change_summary") else "")
            ),
        })
        edges.append((root_id, page_id))

    if len(G.nodes) <= 1:
        return {"nodes": nodes, "edges": [], "pos": {root_id: (0.0, 0.0)}, "empty": True}

    pos = nx.spring_layout(G, seed=42, k=0.9 / max(len(G.nodes) ** 0.5, 1))
    pos = {n: (float(p[0]), float(p[1])) for n, p in pos.items()}

    return {"nodes": nodes, "edges": edges, "pos": pos, "empty": False}


def _score_to_color(score: float) -> str:
    if score >= 80:
        return "#1a7f37"
    if score >= 60:
        return "#9a6700"
    return "#cf222e"