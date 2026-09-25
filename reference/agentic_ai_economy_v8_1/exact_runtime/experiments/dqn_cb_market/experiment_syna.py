#!/usr/bin/env python3
"""EXPERIMENT v4 - SYNA system on Base fork. $100 total ($90 agents / $10 CB).
Currencies: USDC, WETH, SYNA (native). Venues:
 - 3 internal AMM pools: SYNA/USDC, SYNA/WETH, WETH/USDC (0.3% fee stays in pool)
 - OTC board any-price any-pair (taker commission -> SYSTEM FUND)
 - 3 external venues at exogenous oracles (Kraken WETH real blocks; SYNA GBM; 0.1% ext fee leaves system)
Credit (any currency): P2P lend/borrow (150% coll, 120% liq-seize), P2P deposits (trust),
 CB credit (130% coll), CB deposits (trust), invest-in-CB (CB owes + rate; shortfall -> emergency SYNA mint).
SYNA supply: agent mint = 150% collateral Maker-style; CB mint <=2% x5/episode; burn anytime;
 CB buyback-and-burn from treasury. Goal: max WORLD wealth USD (SYNA marked at EXTERNAL price).
DQN traders (22 actions, own rates) + DQN CB (90 = comm x liq x rates x syna-policy).
"""
import json, os
import numpy as np
HERE = os.path.dirname(os.path.abspath(__file__))
D = json.load(open(os.path.join(HERE, os.environ.get("BLOCKS", "real_blocks.json"))))
CANDLES = sorted(D["candles"], key=lambda c: c["t"])
CTS = [c["t"] for c in CANDLES]; CPX = [c["c"] for c in CANDLES]
import bisect
def price_at(ts):
    return CPX[max(0, bisect.bisect_right(CTS, ts) - 1)]
WINS = D["windows"]
N_TR = 6; EP_TRAIN = int(os.environ.get("EPS", "6")); STEPS = int(os.environ.get("STEPS", str(len(WINS[0]))))
# join consecutive windows into STEPS-long episodes (real 80->120+ min horizons)
_flat = [b for _w in WINS for b in _w]
_EPW = [_flat[i:i + STEPS] for i in range(0, len(_flat), STEPS) if len(_flat[i:i + STEPS]) == STEPS]
if len(_EPW) > 1:
    WINS = _EPW
assert all(len(w) == STEPS for w in WINS), "window/steps mismatch"
S = float(os.environ.get("SCALE", "1"))  # capital scale: 1 = $100, 10 = $1000
UPDN = int(os.environ.get("UPDN", "4"))  # DQN update every N env steps
GASU = dict(post=120000, take=150000, cancel=60000, swap=150000, loan=160000, lp=150000, mint=100000, ext=150000)
L1X = 1.3; YR = 365.25 * 24 * 3600
EXPIRY = 90
COMM_LV = [0, 10, 30, 60, 100]
RATES = [(0.02, 0.03), (0.08, 0.10), (0.18, 0.25)]
MARKUP = [0.02, 0.02, 0.05, 0.05, 0.10, 0.10]
GAMMA = 0.99; HID = 64; BATCH = 48; BUF = 20000; SYNC = 500
FLMAX = float(os.environ.get("FLMAX", "1000"))  # flash loan hard cap $ per agent
SYNA0 = 0.10; SYNA_SIG = 1.5
CUR = ("USDC", "WETH", "SYNA")

class MLP:
    def __init__(self, inp, hid, out, seed):
        g = np.random.default_rng(seed)
        self.W1 = g.normal(0, np.sqrt(2 / inp), (inp, hid)); self.b1 = np.zeros(hid)
        self.W2 = g.normal(0, np.sqrt(2 / hid), (hid, hid)); self.b2 = np.zeros(hid)
        self.W3 = g.normal(0, 1 / hid, (hid, out)); self.b3 = np.zeros(out)
        self.m = [np.zeros_like(p) for p in self.p()]; self.v = [np.zeros_like(p) for p in self.p()]; self.t = 0
    def p(self): return [self.W1, self.b1, self.W2, self.b2, self.W3, self.b3]
    def fwd(self, x):
        z1 = x @ self.W1 + self.b1; a1 = np.maximum(z1, 0)
        z2 = a1 @ self.W2 + self.b2; a2 = np.maximum(z2, 0)
        return z1, a1, z2, a2, a2 @ self.W3 + self.b3
    def q(self, x): return self.fwd(x)[4]
    def fit(self, x, yt, lr=3e-4):
        z1, a1, z2, a2, out = self.fwd(x); n = len(x); d = (out - yt) / n
        gW3 = a2.T @ d; gb3 = d.sum(0); dz2 = (d @ self.W3.T) * (z2 > 0)
        gW2 = a1.T @ dz2; gb2 = dz2.sum(0); dz1 = (dz2 @ self.W2.T) * (z1 > 0)
        gW1 = x.T @ dz1; gb1 = dz1.sum(0); self.t += 1
        for i, gv in enumerate([gW1, gb1, gW2, gb2, gW3, gb3]):
            self.m[i] = 0.9 * self.m[i] + 0.1 * gv; self.v[i] = 0.999 * self.v[i] + 0.001 * gv * gv
            mh = self.m[i] / (1 - 0.9 ** self.t); vh = self.v[i] / (1 - 0.999 ** self.t)
            [self.W1, self.b1, self.W2, self.b2, self.W3, self.b3][i] -= lr * mh / (np.sqrt(vh) + 1e-8)
    def copy_from(self, o):
        for a, b in zip(self.p(), o.p()): a[:] = b

class DQN:
    def __init__(self, ns, na, seed):
        self.net = MLP(ns, HID, na, seed); self.tgt = MLP(ns, HID, na, seed + 777)
        self.tgt.copy_from(self.net); self.buf = []; self.na = na
        self.rg = np.random.default_rng(seed + 999); self.steps = 0
    def act(self, s, eps):
        if self.rg.random() < eps: return int(self.rg.integers(self.na))
        return int(np.argmax(self.net.q(s[None])[0]))
    def push(self, s, a, r, s2, d):
        self.buf.append((s, a, r, s2, d))
        if len(self.buf) > BUF: self.buf.pop(0)
    def upd(self):
        if len(self.buf) < BATCH * 2: return
        self.steps += 1
        idx = self.rg.integers(0, len(self.buf), BATCH)
        S = np.array([self.buf[i][0] for i in idx]); A = np.array([self.buf[i][1] for i in idx])
        R = np.array([self.buf[i][2] for i in idx]); S2 = np.array([self.buf[i][3] for i in idx])
        D = np.array([self.buf[i][4] for i in idx])
        tgt = self.net.q(S).copy()
        tgt[np.arange(BATCH), A] = R + GAMMA * (1 - D) * self.tgt.q(S2).max(1)
        self.net.fit(S, tgt)
        if self.steps % SYNC == 0: self.tgt.copy_from(self.net)

class Env:
    def __init__(self, win, synseed, drift=0.0):
        self.blk = win; self.t = 0
        self.px = price_at(win[0]["ts"]); self.px0 = self.px
        # exogenous SYNA/USD path + regime drift (e.g. +-8% bull/bear over episode, disclosed)
        rg = np.random.default_rng(synseed); sp = [SYNA0]
        for k in range(STEPS):
            a = win[k]["ts"]; b = win[min(k + 1, STEPS - 1)]["ts"]
            dt = max(1, b - a) / YR
            sp.append(sp[-1] * float(np.exp(-0.5 * SYNA_SIG ** 2 * dt + SYNA_SIG * np.sqrt(dt) * rg.normal() + drift / STEPS)))
        self.spx = sp; self.sp0 = sp[0]
        self.rets = []; self.srets = []
        self.tr = [dict(usdc=12.0 * S, weth=0.00104 * S, syna=5.0 * S, lock=dict(USDC=0.0, WETH=0.0, SYNA=0.0),
                        coll=dict(USDC=0.0, WETH=0.0, SYNA=0.0), esc=0.0, lp=dict(), syndebt=0.0) for _ in range(N_TR)]
        # external noise trader (zero-intelligence flow OUTSIDE world capital; P&L tracked separately)
        self.noise = dict(usdc=20.0 * S, weth=0.008 * S, syna=200.0 * S)
        self.noiseW0 = self.noise["usdc"] + self.noise["weth"] * self.px + self.noise["syna"] * self.spx[0]
        self.noiseW = self.noiseW0
        self._rg = np.random.default_rng(synseed + 54321)
        self.cb = dict(usdc=4.5 * S, weth=0.0009 * S, syna=12.0 * S, lock=dict(USDC=0.0, WETH=0.0, SYNA=0.0), lp=dict())
        # CB seeds internal pools (must afford: asserts fail loudly, never negative)
        self.pools = dict()
        self._mkpool("SYNA/USDC", "SYNA", 5.0 * S, "USDC", 0.5 * S, self.cb)
        self._mkpool("SYNA/WETH", "SYNA", 5.0 * S, "WETH", 0.0002 * S, self.cb)
        self._mkpool("WETH/USDC", "WETH", 0.0002 * S, "USDC", 0.5 * S, self.cb)
        # genesis LP: every agent seeds SU pool (depth for FL/LP game; W0-neutral via shares)
        for _i in range(N_TR):
            self.lp_add(_i, "SYNA/USDC", 2.0 * S)
        # SYSTEM FUND: fee sink + SYNA mint-lender. Genesis: $1 USDC (from CB) + 30 SYNA founding mint
        self.fund = dict(USDC=1.0 * S, SYNA=30.0 * S, WETH=0.0)
        self.cb["usdc"] -= 1.0 * S
        assert self.cb["usdc"] >= 0 and self.cb["weth"] >= 0 and self.cb["syna"] >= 0, "CB insolvent at genesis"
        if os.environ.get("PEG", "") == "-50":
            # diagnostic dislocation: halve SU-pool USDC into FUND (W0-neutral), prem = -50%
            p = self.pools["SYNA/USDC"]
            mv = p["rq"] * 0.5; p["rq"] -= mv; self.fund["USDC"] += mv
        self.supply = (sum(a["syna"] for a in self.tr) + self.cb["syna"] + self.fund["SYNA"]
                       + sum(p["rb"] for p in self.pools.values() if p["base"] == "SYNA")
                       + sum(p["rq"] for p in self.pools.values() if p["quote"] == "SYNA"))
        self.supply0 = self.supply  # genesis baseline (no double-counting, ever)
        self.burned = 0.0; self.minted_cb = 0; self.emgmint = 0.0
        self.comm_bps = 100; self.rate_i = 1
        self.otc = []; self.oid = 0
        self.offers = []; self.debts = []
        self.vol_otc = 0.0; self.vol_ext = 0.0; self.vol_amm = 0.0
        self.comms = 0.0; self.extfees = 0.0; self.cgas = 0.0; self.trades = 0
        self.int_p2p = 0.0; self.int_cb = 0.0; self.f_p2p = 0.0; self.f_cb = 0.0
        self.f_dep = 0.0; self.f_incb = 0.0; self.defaults = 0; self.liqs = 0
        self.mints = 0; self.burns = 0; self.buybacks = 0
        self.fl_vol = 0.0; self.fl_profits = 0.0; self.fl_reverts = 0; self.lp_n = 0
        self.extarb = 0.0  # value extracted from pools by EXTERNAL arb competition (leaves system)
        self._dbg = dict(eb=0.0, es=0.0, bn=0.0, cbm=0.0)
        self.created = 0.0; self.destroyed = 0.0  # seigniorage vs supply-destruction (USD)
        self.provided = 0; self.swaps = 0
        self.cb_hist = []
    def _mkpool(self, name, bcur, bamt, qcur, qamt, owner):
        o = self.cb if owner is self.cb else self.tr[owner]
        assert o[bcur.lower()] >= bamt and o[qcur.lower()] >= qamt, "insolvent pool seed %s" % name
        o[bcur.lower()] -= bamt; o[qcur.lower()] -= qamt
        o["lp"][name] = 1.0
        self.pools[name] = dict(base=bcur, quote=qcur, rb=bamt, rq=qamt, shares={id(o): 1.0})
    def oracle(self):
        return dict(USDC=1.0, WETH=self.px, SYNA=self.spx[self.t])
    def fund_usd(self):
        o = self.oracle()
        rec = sum(L["pr"] for L in self.debts if not L["done"] and L["kind"] == "synm") * o["SYNA"]
        return self.fund["USDC"] + self.fund["SYNA"] * o["SYNA"] + self.fund["WETH"] * o["WETH"] + rec
    def gas_u(self, k):
        return GASU[k] * self.blk[self.t]["baseFee"] * L1X / 1e18 * self.px
    def val(self, cur, amt):
        return amt * self.oracle()[cur]
    def pool_val(self, name):
        p = self.pools[name]; o = self.oracle()
        return p["rb"] * o[p["base"]] + p["rq"] * o[p["quote"]]
    def lp_val(self, holder):
        H = self.cb if holder == "cb" else self.tr[holder]
        tot = 0.0
        for n in self.pools:
            s = sum(self.pools[n]["shares"].values())
            if s > 0: tot += H["lp"].get(n, 0.0) / s * self.pool_val(n)
        return tot
    def opencoll(self, i):
        c = dict(USDC=0.0, WETH=0.0, SYNA=0.0)
        for L in self.debts:
            if not L["done"] and L["bor"] == i:
                for k in c: c[k] += L["coll"][k]
        return c
    def phys_syna(self):
        # every physical SYNA unit anywhere INCL. external noise wallet (for supply invariant audit)
        s = sum(a["syna"] + a["lock"]["SYNA"] for a in self.tr) + self.cb["syna"] + self.cb["lock"]["SYNA"] + self.fund["SYNA"] + self.noise["syna"]
        for L in self.debts:
            if not L["done"]: s += L["coll"]["SYNA"]
        for p in self.pools.values():
            if p["base"] == "SYNA": s += p["rb"]
            if p["quote"] == "SYNA": s += p["rq"]
        return s
    def wealth(self, i):
        a = self.tr[i]; o = self.oracle(); cl = self.opencoll(i)
        return (a["usdc"] + a["lock"]["USDC"] + a["esc"]
                + (a["weth"] + a["lock"]["WETH"] + cl["WETH"]) * o["WETH"]
                + (a["syna"] + a["lock"]["SYNA"] + cl["SYNA"] - a["syndebt"]) * o["SYNA"]
                + (cl["USDC"]) + self.lp_val(i))
    def cbwealth(self):
        c = self.cb; o = self.oracle()
        return (c["usdc"] + c["lock"]["USDC"]
                + (c["weth"] + c["lock"]["WETH"]) * o["WETH"]
                + (c["syna"] + c["lock"]["SYNA"]) * o["SYNA"] + self.lp_val("cb"))
    def world(self):
        return sum(self.wealth(i) for i in range(N_TR)) + self.cbwealth() + self.fund_usd()
    def gini(self):
        w = np.sort(np.array([self.wealth(i) for i in range(N_TR)]))
        return float((2 * np.arange(1, N_TR + 1) @ w) / (N_TR * w.sum()) - (N_TR + 1) / N_TR)
    def vol20(self):
        r = np.array(self.rets[-20:])
        return float(r.std() * 10000) if len(r) > 1 else 0.0
    def noise_step(self):
        # zero-intelligence external flow: random small swap in random pool (sustains dislocations)
        if self._rg.random() > 0.35: return
        names = list(self.pools.keys())
        name = names[int(self._rg.integers(len(names)))]
        p = self.pools[name]; o = self.oracle()
        u = (0.1 + self._rg.random() * 0.3) * S
        g = self.gas_u("swap")
        if self.noise["usdc"] < g: return
        self.noise["usdc"] -= g; self.cgas += g
        if self._rg.random() < 0.5:  # buy base with quote
            cur = p["quote"]
            if self.noise[cur.lower()] < u: return
            fee = u * 0.003; net = u - fee
            dx = p["rb"] * net / (p["rq"] + net)
            self.noise[cur.lower()] -= u; p["rq"] += u; p["rb"] -= dx  # fee accrues to LPs
            self.noise[p["base"].lower()] += dx; self.swaps += 1
        else:
            q = (u / o[p["base"]]) * 0.5
            if self.noise[p["base"].lower()] < q: return
            gross = p["rq"] * q / (p["rb"] + q); fee = gross * 0.003; dy = gross - fee
            self.noise[p["base"].lower()] -= q; self.noise[p["quote"].lower()] += dy
            p["rb"] += q; p["rq"] -= dy; self.swaps += 1
    def noise_wealth(self):
        o = self.oracle()
        return self.noise["usdc"] + self.noise["weth"] * o["WETH"] + self.noise["syna"] * o["SYNA"]
    def ext_arb(self):
        # EXTERNAL gas-aware searcher: closes prem beyond +/-2% only if extraction >= $0.02.
        # Dust below that is left for OUR agents' flash loans (their niche). Profit leaves system.
        # Runs AFTER agents+noise each step: our agents get first look.
        o = self.oracle()
        for p in self.pools.values():
            if p["rb"] <= 1e-12 or p["rq"] <= 1e-12: continue
            fair = o[p["base"]] / o[p["quote"]]
            px = p["rq"] / p["rb"]
            if px > fair * 1.02:  # base overpriced: sell base until prem = +2%
                lo_q, hi_q = 0.0, 10.0 * p["rb"] + 1e-9
                for _ in range(60):
                    q = (lo_q + hi_q) / 2
                    dy = p["rq"] * q * 0.997 / (p["rb"] + q * 0.997)
                    np_ = (p["rq"] - dy) / (p["rb"] + q)
                    if np_ > fair * 1.02: lo_q = q
                    else: hi_q = q
                q = (lo_q + hi_q) / 2
                if q > 1e-12:
                    dy = p["rq"] * q * 0.997 / (p["rb"] + q * 0.997)
                    if (dy - q * fair) * o[p["quote"]] < 0.02: continue  # dust: not worth searcher gas
                    p["rb"] += q; p["rq"] -= dy
                    self.extarb += (dy - q * fair) * o[p["quote"]]
                    if p["base"] == "SYNA": self.supply += q  # inflow from outside counted
                    self.swaps += 1
            elif px < fair * 0.98:  # base cheap: buy with quote until prem = -2%
                lo_u, hi_u = 0.0, 10.0 * p["rq"] + 1e-9
                for _ in range(60):
                    u = (lo_u + hi_u) / 2
                    dx = p["rb"] * u * 0.997 / (p["rq"] + u * 0.997)
                    np_ = (p["rq"] + u) / max(p["rb"] - dx, 1e-12)
                    if np_ < fair * 0.98: lo_u = u
                    else: hi_u = u
                u = (lo_u + hi_u) / 2
                if u > 1e-12:
                    dx = p["rb"] * u * 0.997 / (p["rq"] + u * 0.997)
                    if (dx * fair - u) * o[p["quote"]] < 0.02: continue  # dust
                    p["rq"] += u; p["rb"] -= dx
                    self.extarb += (dx * fair - u) * o[p["quote"]]
                    if p["base"] == "SYNA": self.supply -= dx  # outflow leaves system-tracked supply
                    self.swaps += 1
    def otc_post(self, who, give, giveAmt, want, wantAmt):
        # gas only on execution: off-chain simulation is free, mined txs cost
        A = self.cb if who == "cb" else self.tr[who]
        g = self.gas_u("post")
        if A["usdc"] < g: return False
        if give == "USDC":
            if A["usdc"] < giveAmt + g: return False
            A["usdc"] -= giveAmt + g
        else:
            if A[give.lower()] < giveAmt: return False
            A[give.lower()] -= giveAmt; A["usdc"] -= g
        self.cgas += g
        A["lock"][give] += giveAmt
        self.otc.append(dict(id=self.oid, who=who, give=give, gamt=giveAmt, want=want, wamt=wantAmt, t=self.t))
        self.oid += 1; return True
    def otc_best(self, i):
        A = self.tr[i]; o = self.oracle(); best = None; edge = 0
        for x in self.otc:
            if x["who"] == i: continue
            if A[x["want"].lower()] < x["wamt"]: continue
            e = self.val(x["give"], x["gamt"]) - self.val(x["want"], x["wamt"])
            if e > edge: edge = e; best = x
        return best, edge
    def otc_accept(self, who, x=None, i=None):
        T = self.cb if who == "cb" else self.tr[who]
        g = self.gas_u("take")
        if T["usdc"] < g: return False
        if x is None:
            x, edge = self.otc_best(who)
            if x is None: return False
        M = self.cb if x["who"] == "cb" else self.tr[x["who"]]
        cm = self.val(x["give"], x["gamt"]) * self.comm_bps / 10000
        if T[x["want"].lower()] < x["wamt"] or T["usdc"] < cm + g: return False
        T["usdc"] -= g; self.cgas += g
        T[x["want"].lower()] -= x["wamt"]; T["usdc"] -= cm
        T[x["give"].lower()] += x["gamt"]
        M[x["want"].lower()] += x["wamt"]; M["lock"][x["give"]] -= x["gamt"]
        self.fund["USDC"] += cm; self.comms += cm
        self.vol_otc += self.val(x["give"], x["gamt"]); self.trades += 1
        self.otc = [y for y in self.otc if y["id"] != x["id"]]
        return True
    def otc_cancel(self, who):
        A = self.cb if who == "cb" else self.tr[who]
        g = self.gas_u("cancel")
        if A["usdc"] < g: return False
        own = [x for x in self.otc if x["who"] == who]
        if not own: return False
        A["usdc"] -= g; self.cgas += g
        x = min(own, key=lambda y: y["t"])
        A["lock"][x["give"]] -= x["gamt"]; A[x["give"].lower()] += x["gamt"]
        self.otc = [y for y in self.otc if y["id"] != x["id"]]
        return True
    def expire(self):
        keep = []
        for x in self.otc:
            if self.t - x["t"] > EXPIRY:
                A = self.cb if x["who"] == "cb" else self.tr[x["who"]]
                A["lock"][x["give"]] -= x["gamt"]; A[x["give"].lower()] += x["gamt"]
            else: keep.append(x)
        self.otc = keep
    # ---------- internal AMM ----------
    def amm_swap(self, i, name, buY):
        a = self.tr[i]; p = self.pools[name]; g = self.gas_u("swap")
        if a["usdc"] < g: return False
        if buY:  # spend quote, get base
            u = 0.5 * S if p["quote"] == "USDC" else 0.5 * S / self.oracle()[p["quote"]]
            if a[p["quote"].lower()] < u: return False  # simulated, skipped free
            a["usdc"] -= g; self.cgas += g
            fee = u * 0.003; net = u - fee
            dx = p["rb"] * net / (p["rq"] + net)
            a[p["quote"].lower()] -= u; p["rq"] += u; p["rb"] -= dx  # fee accrues to LPs
            a[p["base"].lower()] += dx; self.swaps += 1
            self.vol_amm += self.val(p["base"], dx); return True
        else:
            q = 5.0 * S if p["base"] == "SYNA" else 0.0002 * S
            if a[p["base"].lower()] < q: return False
            a["usdc"] -= g; self.cgas += g
            gross = p["rq"] * q / (p["rb"] + q); fee = gross * 0.003; dy = gross - fee
            a[p["base"].lower()] -= q; a[p["quote"].lower()] += dy
            p["rb"] += q; p["rq"] -= dy; self.swaps += 1
            self.vol_amm += self.val(p["base"], q); return True
    def fl_arb_pool(self, i, name):
        # ATOMIC Balancer-style flash loan (up to $10k, zero fee): arb pool vs external, revert if unprofitable
        a = self.tr[i]; p = self.pools[name]; o = self.oracle(); g = self.gas_u("swap")
        if a["usdc"] < g: return False
        oq = o[p["quote"]]; ob = o[p["base"]]
        best = None
        for u in (0.05 * S, 0.1 * S, 0.5 * S, 1.0 * S, 2.0 * S, 5.0 * S, 10.0 * S, 50.0 * S, 100.0 * S, 500.0 * S, 1000.0):
            if u > FLMAX: continue  # hard cap: flash loan max per agent (any SCALE)
            uq = u / oq  # USD size -> quote units
            dx = p["rb"] * uq * 0.997 / (p["rq"] + uq * 0.997)
            rev1 = dx * ob * 0.999 - u
            q = u * 0.999 / ob
            dy = p["rq"] * q * 0.997 / (p["rb"] + q * 0.997)
            rev2 = dy * oq - u
            if rev1 > 0 and (best is None or rev1 > best[0]): best = (rev1, u, uq, 1, dx, 0.0)
            if rev2 > 0 and (best is None or rev2 > best[0]): best = (rev2, u, uq, 2, q, dy)
        if best is None: self.fl_reverts += 1; return False  # simulated, skipped free
        a["usdc"] -= g; self.cgas += g
        rev, u, uq, d, qq, dy = best
        if d == 1:
            p["rq"] += uq; p["rb"] -= qq
            fee = qq * ob * 0.001; self.extfees += fee
            a["usdc"] += qq * ob - fee - u
            self.supply -= qq  # sold externally: outflow leaves system-tracked supply
        else:
            a["usdc"] -= u
            fee = u * 0.001; self.extfees += fee
            p["rb"] += qq; p["rq"] -= dy
            a["usdc"] += dy * oq
            self.supply += qq  # bought externally: inflow counted
        self.fl_vol += u; self.fl_profits += rev; self.trades += 1
        return True
    def fl_otc(self, i):
        # ATOMIC flash: borrow payment, take best OTC edge, repay from proceeds, keep profit.
        # Payment leg routed via EXTERNAL venue (supply-tracked); revert free if unprofitable.
        a = self.tr[i]; g = self.gas_u("take")
        if a["usdc"] < g: return False
        x, edge = self.otc_best(i)
        if x is None:
            self.fl_reverts += 1; return False
        need = self.val(x["want"], x["wamt"])
        if need > FLMAX:
            self.fl_reverts += 1; return False
        o = self.oracle()
        paid = self.val(x["want"], x["wamt"]); recvd = self.val(x["give"], x["gamt"])
        cm = recvd * self.comm_bps / 10000
        fee_b = paid * 0.001
        fee_s = 0.0 if x["give"] == "USDC" else (paid + fee_b + cm + g) * 0.001
        if recvd - paid - cm - g - fee_b - fee_s <= 0:
            self.fl_reverts += 1; return False
        a["usdc"] -= g; self.cgas += g
        M = self.cb if x["who"] == "cb" else self.tr[x["who"]]
        # 1. flash-buy payment currency externally (supply-tracked inflow)
        self.extfees += fee_b
        if x["want"] == "SYNA": self.supply += x["wamt"]
        L = paid + fee_b  # flash debt in USDC
        # 2. pay maker, release escrow, taker receives give
        M[x["want"].lower()] += x["wamt"]; M["lock"][x["give"]] -= x["gamt"]
        a[x["give"].lower()] += x["gamt"]
        # 3. settle flash + fees (auto-liquidate part of proceeds if non-USDC)
        if x["give"] != "USDC":
            s = min(x["gamt"], (L + cm) / (o[x["give"]] * 0.999))
            a[x["give"].lower()] -= s
            _gs = s * o[x["give"]]; _fs = _gs * 0.001
            a["usdc"] += _gs - _fs; self.extfees += _fs
            if x["give"] == "SYNA": self.supply -= s
            a["usdc"] -= L + cm
        else:
            # USDC-give already credited in step 2: only repay flash + commission here
            a["usdc"] -= L + cm
        self.fund["USDC"] += cm; self.comms += cm
        self.vol_otc += recvd; self.trades += 1
        self.fl_vol += need; self.fl_profits += recvd - paid - cm - g - fee_b - fee_s
        self.otc = [y for y in self.otc if y["id"] != x["id"]]
        return True
    def lp_add(self, who, name, u):
        A = self.cb if who == "cb" else self.tr[who]
        p = self.pools[name]; g = self.gas_u("lp"); o = self.oracle()
        if A["usdc"] < g: return False
        ratio = (p["rb"] * o[p["base"]]) / p["rq"]  # base-value per quote unit
        bneed = u * ratio / o[p["base"]]
        if A[p["quote"].lower()] < u or A[p["base"].lower()] < bneed: return False
        A["usdc"] -= g; self.cgas += g
        A[p["quote"].lower()] -= u; A[p["base"].lower()] -= bneed
        share = u / p["rq"]
        p["rq"] += u; p["rb"] += bneed
        A["lp"][name] = A["lp"].get(name, 0.0) + share
        p["shares"][id(A)] = p["shares"].get(id(A), 0.0) + share
        self.lp_n += 1
        return True
    def lp_out(self, who, name, frac=0.5):
        A = self.cb if who == "cb" else self.tr[who]
        p = self.pools[name]; g = self.gas_u("lp")
        if A["usdc"] < g: return False
        s = A["lp"].get(name, 0.0) * frac
        if s <= 1e-12: return False
        A["usdc"] -= g; self.cgas += g
        tot = sum(p["shares"].values())
        f = s / tot
        A[p["quote"].lower()] += p["rq"] * f; A[p["base"].lower()] += p["rb"] * f
        p["rq"] *= (1 - f); p["rb"] *= (1 - f)
        A["lp"][name] -= s; p["shares"][id(A)] -= s
        self.lp_n += 1
        return True
    def fl_opp(self):
        # max flash-arb gross opportunity across pools AND sizes (mirrors fl_arb scan)
        o = self.oracle(); best = 0.0
        for u in (0.05 * S, 0.5 * S, 2.0 * S, 10.0 * S, 100.0 * S):
            for p in self.pools.values():
                uq = u / o[p["quote"]]
                dx = p["rb"] * uq * 0.997 / (p["rq"] + uq * 0.997)
                best = max(best, dx * o[p["base"]] * 0.999 - u)
                q = u * 0.999 / o[p["base"]]
                dy = p["rq"] * q * 0.997 / (p["rb"] + q * 0.997)
                best = max(best, dy * o[p["quote"]] - u)
        return best
    # ---------- external venues (infinite depth, oracle +/- 0.1% fee leaves system) ----------
    def ext_trade(self, i, cur, buy, u=None):
        u = (1.0 * S) if u is None else u
        a = self.tr[i]; o = self.oracle(); g = self.gas_u("ext")
        if cur == "USDC" or a["usdc"] < g: return False
        if buy:
            if a["usdc"] < u + g: return False
            a["usdc"] -= g; self.cgas += g
            fee = u * 0.001; a["usdc"] -= u; self.extfees += fee
            q = (u - fee) / o[cur]
            a[cur.lower()] += q; self.vol_ext += u
            if cur == "SYNA":
                self.supply += q; self._dbg["eb"] += q  # external inflow counted
            return True
        else:
            q = u / o[cur]
            if a[cur.lower()] < q: return False
            a["usdc"] -= g; self.cgas += g
            a[cur.lower()] -= q; gross = q * o[cur]; fee = gross * 0.001
            a["usdc"] += gross - fee; self.extfees += fee; self.vol_ext += gross
            if cur == "SYNA":
                self.supply -= q; self._dbg["es"] += q  # outflow leaves system-tracked supply
            return True
    # ---------- credit (any currency) ----------
    def _move(self, who, cur, amt):
        A = self.cb if who == "cb" else self.tr[who]
        A[cur.lower()] += amt
    def lend_offer(self, i, cur="USDC", amt=5.0 * S):
        a = self.tr[i]; g = self.gas_u("loan")
        if a["usdc"] < g: return False
        rate = RATES[self.rate_i][0] + MARKUP[i]
        if a[cur.lower()] < amt or (cur == "USDC" and a["usdc"] < amt + g): return False
        if cur == "USDC": a["usdc"] -= amt + g
        else: a[cur.lower()] -= amt; a["usdc"] -= g
        self.cgas += g; a["esc"] += self.val(cur, amt)
        self.offers.append(dict(lender=i, cur=cur, amt=amt, rate=rate, t0=self.t)); return True
    def borrow_best(self, i):
        a = self.tr[i]; o = self.oracle()
        g = self.gas_u("loan")
        if a["usdc"] < g: return False
        cands = [x for x in self.offers if x["lender"] != i]
        if not cands: return False
        x = min(cands, key=lambda y: y["rate"])
        need = self.val(x["cur"], x["amt"]) * 1.5
        have = a["weth"] * o["WETH"] + a["usdc"] + a["syna"] * o["SYNA"] * 0.5
        if have < need: return False
        a["usdc"] -= g; self.cgas += g
        self.offers.remove(x)
        L = self.tr[x["lender"]]; L["esc"] -= self.val(x["cur"], x["amt"])
        # lock collateral: weth first, then usdc, then syna(50% haircut counted above, lock full value)
        rem = need; coll = dict(USDC=0.0, WETH=0.0, SYNA=0.0)
        for c in ("WETH", "USDC", "SYNA"):
            v = a[c.lower()] * o[c] * (0.5 if c == "SYNA" else 1.0)
            take = min(v, rem); amt = take / o[c] * (2.0 if c == "SYNA" else 1.0)
            amt = min(amt, a[c.lower()]); a[c.lower()] -= amt; coll[c] += amt
            rem -= amt * o[c] * (0.5 if c == "SYNA" else 1.0)
            if rem <= 1e-9: break
        a[x["cur"].lower()] += x["amt"]
        self.debts.append(dict(kind="p2p", bor=i, lender=x["lender"], cur=x["cur"], pr=x["amt"],
                               rate=x["rate"], t0=self.blk[self.t]["ts"], term=240, coll=coll, done=False))
        self.f_p2p += self.val(x["cur"], x["amt"]); return True
    def deposit_peer(self, i, amt=5.0 * S):
        a = self.tr[i]; g = self.gas_u("loan")
        if a["usdc"] < g: return False
        js = [j for j in range(N_TR) if j != i]
        j = min(js, key=lambda k: self.wealth(k))
        if a["usdc"] < amt + g: return False
        a["usdc"] -= amt + g; self.cgas += g
        self.tr[j]["usdc"] += amt
        self.debts.append(dict(kind="dep", bor=j, lender=i, cur="USDC", pr=amt, rate=0.12,
                               t0=self.blk[self.t]["ts"], term=480, coll=dict(USDC=0.0, WETH=0.0, SYNA=0.0), done=False))
        self.f_dep += amt; return True
    def cb_borrow(self, i, amt=1.0 * S):
        a = self.tr[i]; rl, rd = RATES[self.rate_i]; g = self.gas_u("loan"); o = self.oracle()
        if a["usdc"] < g: return False
        cur = "USDC"
        need = amt * 1.3
        have = a["weth"] * o["WETH"] + a["usdc"] + a["syna"] * o["SYNA"] * 0.5
        if have < need or self.cb["usdc"] < amt: return False
        a["usdc"] -= g; self.cgas += g
        rem = need; coll = dict(USDC=0.0, WETH=0.0, SYNA=0.0)
        for c in ("WETH", "USDC", "SYNA"):
            v = a[c.lower()] * o[c] * (0.5 if c == "SYNA" else 1.0)
            take = min(v, rem); u = take / o[c] * (2.0 if c == "SYNA" else 1.0)
            u = min(u, a[c.lower()]); a[c.lower()] -= u; coll[c] += u
            rem -= u * o[c] * (0.5 if c == "SYNA" else 1.0)
            if rem <= 1e-9: break
        a["usdc"] += amt; self.cb["usdc"] -= amt
        self.debts.append(dict(kind="cbloan", bor=i, lender="cb", cur="USDC", pr=amt, rate=rl,
                               t0=self.blk[self.t]["ts"], term=480, coll=coll, done=False))
        self.f_cb += amt; return True
    def cb_deposit(self, i, amt=1.0 * S):
        # CB places a (trust, uncollateralized) deposit WITH the agent; agent repays + dep rate
        a = self.tr[i]; rl, rd = RATES[self.rate_i]; g = self.gas_u("loan")
        if a["usdc"] < g: return False
        if self.cb["usdc"] < amt: return False
        a["usdc"] -= g; self.cgas += g
        a["usdc"] += amt; self.cb["usdc"] -= amt
        self.debts.append(dict(kind="cbdep", bor=i, lender="cb", cur="USDC", pr=amt, rate=rd,
                               t0=self.blk[self.t]["ts"], term=480, coll=dict(USDC=0.0, WETH=0.0, SYNA=0.0), done=False))
        self.f_cb += amt; return True
    def invest_cb(self, i, amt=5.0 * S):
        a = self.tr[i]; rl, rd = RATES[self.rate_i]; g = self.gas_u("loan")
        if a["usdc"] < g: return False
        if a["usdc"] < amt + g: return False
        a["usdc"] -= amt + g; self.cgas += g; self.cb["usdc"] += amt
        self.debts.append(dict(kind="incb", bor="cb", lender=i, cur="USDC", pr=amt, rate=rd,
                               t0=self.blk[self.t]["ts"], term=480, coll=dict(USDC=0.0, WETH=0.0, SYNA=0.0), done=False))
        self.f_incb += amt; return True
    # ---------- SYNA mint (borrow existing SYNA from FUND inventory, Maker-style) / burn ----------
    def syn_mint(self, i):
        a = self.tr[i]; rl, rd = RATES[self.rate_i]; g = self.gas_u("mint"); o = self.oracle()
        if a["usdc"] < g: return False
        amt = 2.5 * S; need = amt * 1.5  # $2.5 SYNA vs $3.75 collateral (fund inventory-gated)
        q = amt / o["SYNA"]
        if self.fund["SYNA"] < q: return False  # facility closed: fund has no inventory
        have = a["weth"] * o["WETH"] + a["usdc"]
        if have < need + g: return False
        a["usdc"] -= g; self.cgas += g
        rem = need; coll = dict(USDC=0.0, WETH=0.0, SYNA=0.0)
        for c in ("WETH", "USDC"):
            v = a[c.lower()] * o[c]; take = min(v, rem)
            u = min(take / o[c], a[c.lower()]); a[c.lower()] -= u; coll[c] += u; rem -= u * o[c]
            if rem <= 1e-9: break
        q = amt / o["SYNA"]; a["syna"] += q; a["syndebt"] += q
        self.fund["SYNA"] -= q  # lent from fund inventory (no new supply)
        self.debts.append(dict(kind="synm", bor=i, lender="fund", pr=q, rate=rl,
                               t0=self.blk[self.t]["ts"], term=480, coll=coll, done=False, cur="SYNA"))
        self.mints += 1; return True
    def syn_repay(self, i):
        a = self.tr[i]
        g = self.gas_u("loan")
        if a["usdc"] < g: return False
        for L in self.debts:
            if L["done"] or L["kind"] != "synm" or L["bor"] != i: continue
            el = self.blk[self.t]["ts"] - L["t0"]; due = L["pr"] * (1 + L["rate"] * el / YR)
            if a["syna"] < due: continue
            a["usdc"] -= g; self.cgas += g
            a["syna"] -= due; a["syndebt"] -= L["pr"]; self.fund["SYNA"] += due  # back to fund + interest
            for c in CUR: a[c.lower()] += L["coll"][c]; L["coll"][c] = 0.0
            L["done"] = True; return True
        return False
    def syn_burn(self, i, amt=5.0 * S):
        a = self.tr[i]; g = self.gas_u("mint")
        if a["usdc"] < g: return False
        if a["syna"] < amt: return False
        a["usdc"] -= g; self.cgas += g
        a["syna"] -= amt; self.supply -= amt; self._dbg["bn"] += amt; self.burned += amt; self.burns += 1
        self.destroyed += amt * self.oracle()["SYNA"]; return True
    def repay_all(self, i):
        a = self.tr[i]; o = self.oracle(); ok = False
        g = self.gas_u("loan")
        if a["usdc"] < g: return False
        pay = None
        for L in self.debts:
            if L["done"] or L["bor"] != i or L["kind"] == "synm": continue
            el = self.blk[self.t]["ts"] - L["t0"]; due = L["pr"] * (1 + L["rate"] * el / YR)
            if a[L["cur"].lower()] >= due:
                pay = L; break
        if pay is None: return False  # nothing repayable: simulated free
        a["usdc"] -= g; self.cgas += g
        for L in self.debts:
            if L["done"] or L["bor"] != i or L["kind"] == "synm": continue
            el = self.blk[self.t]["ts"] - L["t0"]; due = L["pr"] * (1 + L["rate"] * el / YR)
            if a[L["cur"].lower()] >= due:
                a[L["cur"].lower()] -= due
                if L["lender"] == "cb": self.cb["usdc"] += due; self.int_cb += due - L["pr"]
                elif L["lender"] == "sys": pass
                else: self.tr[L["lender"]][L["cur"].lower()] += due; self.int_p2p += (due - L["pr"]) * o.get(L["cur"], 1.0) / o.get(L["cur"], 1.0)
                for c in CUR: a[c.lower()] += L["coll"][c]; L["coll"][c] = 0.0
                L["done"] = True; ok = True
        return ok
    def debt_step(self):
        now = self.blk[self.t]["ts"]; o = self.oracle()
        for L in self.debts:
            if L["done"]: continue
            el = now - L["t0"]
            acc = L["pr"] * L["rate"] * el / YR
            if L["kind"] == "incb":
                if el >= L["term"]:
                    due = L["pr"] + acc
                    if self.cb["usdc"] >= due:
                        self.cb["usdc"] -= due; self.tr[L["lender"]]["usdc"] += due; self.int_cb += acc
                    else:
                        # emergency: sell weth/syna, then seigniorage = mint + SELL externally (balanced)
                        short = due - self.cb["usdc"]
                        got = 0.0
                        sw = min(self.cb["weth"], short / o["WETH"])
                        self.cb["weth"] -= sw; got += sw * o["WETH"]
                        ss = min(self.cb["syna"], max(0.0, short - got) / o["SYNA"])
                        self.cb["syna"] -= ss; got += ss * o["SYNA"]
                        if got < short:
                            m = (short - got) / (o["SYNA"] * 0.999)
                            self.emgmint += m  # NOTE: NOT added to supply (sold externally, never in system)
                            fee = m * o["SYNA"] * 0.001; self.extfees += fee
                            got += m * o["SYNA"] - fee
                            self.created += m * o["SYNA"]  # seigniorage bailout
                        self.cb["usdc"] += got
                        self.cb["usdc"] -= due; self.tr[L["lender"]]["usdc"] += due; self.int_cb += acc
                    L["done"] = True
                continue
            # collateral value (haircut SYNA 50%)
            cv = L["coll"]["USDC"] + L["coll"]["WETH"] * o["WETH"] + L["coll"]["SYNA"] * o["SYNA"] * 0.5
            dv = (L["pr"] + acc) * (o.get(L["cur"], 1.0) if L["cur"] in o else 1.0)
            if sum(L["coll"].values()) > 0 and cv < 1.2 * dv:
                b = self.tr[L["bor"]]
                for c in CUR:
                    if L["lender"] == "cb": self.cb[c.lower()] += L["coll"][c]
                    elif L["lender"] == "fund": self.fund[c] += L["coll"][c]
                    else: self.tr[L["lender"]][c.lower()] += L["coll"][c]
                    L["coll"][c] = 0.0
                if L["kind"] == "synm": b["syndebt"] -= L["pr"]
                L["done"] = True; self.liqs += 1; continue
            if el >= L["term"] * 2:
                due = L["pr"] + acc; b = self.tr[L["bor"]]
                if L["kind"] == "synm":
                    if b["syna"] >= due:
                        b["syna"] -= due; b["syndebt"] -= L["pr"]; self.fund["SYNA"] += due
                        for c in CUR: b[c.lower()] += L["coll"][c]; L["coll"][c] = 0.0
                    else:
                        self.defaults += 1; b["syndebt"] -= L["pr"]  # fund loses lent syna (real loss)
                        for c in CUR: self.fund[c] += L["coll"][c]; L["coll"][c] = 0.0
                    L["done"] = True; continue
                if b[L["cur"].lower()] >= due:
                    b[L["cur"].lower()] -= due
                    if L["lender"] == "cb": self.cb["usdc"] += due; self.int_cb += acc
                    else: self.tr[L["lender"]][L["cur"].lower()] += due; self.int_p2p += acc * (o[L["cur"]] if L["cur"] != "USDC" else 1.0)
                    for c in CUR: b[c.lower()] += L["coll"][c]; L["coll"][c] = 0.0
                else:
                    self.defaults += 1
                    for c in CUR:
                        if L["lender"] == "cb": self.cb[c.lower()] += L["coll"][c]
                        else: self.tr[L["lender"]][c.lower()] += L["coll"][c]
                        L["coll"][c] = 0.0
                L["done"] = True
    def expW(self):
        s = sum(a["weth"] + a["lock"]["WETH"] for a in self.tr) + self.cb["weth"] + self.cb["lock"]["WETH"] + self.fund["WETH"] + self.noise["weth"]
        for L in self.debts:
            if not L["done"]: s += L["coll"]["WETH"]
        for p in self.pools.values():
            if p["base"] == "WETH": s += p["rb"]
            if p["quote"] == "WETH": s += p["rq"]
        return s
    def expS(self):
        s = sum(a["syna"] + a["lock"]["SYNA"] - a["syndebt"] for a in self.tr) + self.cb["syna"] + self.cb["lock"]["SYNA"] + self.fund["SYNA"] + self.noise["syna"]
        for L in self.debts:
            if not L["done"]:
                s += L["coll"]["SYNA"]
                if L["kind"] == "synm": s += L["pr"]  # fund receivable
        for p in self.pools.values():
            if p["base"] == "SYNA": s += p["rb"]
            if p["quote"] == "SYNA": s += p["rq"]
        return s
    def _settle_simpl(self, L, now):
        # force-settle an open non-incb debt at episode end (same economics as maturity)
        o = self.oracle()
        if L["kind"] == "synm":
            b = self.tr[L["bor"]]; due = L["pr"] * (1 + L["rate"] * (now - L["t0"]) / YR)
            if b["syna"] >= due:
                b["syna"] -= due; b["syndebt"] -= L["pr"]; self.fund["SYNA"] += due
                for c in CUR: b[c.lower()] += L["coll"][c]; L["coll"][c] = 0.0
            else:
                self.defaults += 1; b["syndebt"] -= L["pr"]
                for c in CUR: self.fund[c] += L["coll"][c]; L["coll"][c] = 0.0
            L["done"] = True; return True
        acc = L["pr"] * L["rate"] * (now - L["t0"]) / YR; due = L["pr"] + acc
        b = self.tr[L["bor"]]
        if b[L["cur"].lower()] >= due:
            b[L["cur"].lower()] -= due
            if L["lender"] == "cb": self.cb["usdc"] += due; self.int_cb += acc
            else: self.tr[L["lender"]][L["cur"].lower()] += due; self.int_p2p += acc
            for c in CUR: b[c.lower()] += L["coll"][c]; L["coll"][c] = 0.0
        else:
            self.defaults += 1
            for c in CUR:
                if L["lender"] == "cb": self.cb[c.lower()] += L["coll"][c]
                else: self.tr[L["lender"]][c.lower()] += L["coll"][c]
                L["coll"][c] = 0.0
        L["done"] = True; return True
    def agent_exp(self, i):
        # (weth_units, syna_units_net) exposure of agent i incl. LP shares, for differential rewards
        a = self.tr[i]
        w = a["weth"] + a["lock"]["WETH"]
        s = a["syna"] + a["lock"]["SYNA"] - a["syndebt"]
        for L in self.debts:
            if not L["done"] and L["bor"] == i:
                w += L["coll"]["WETH"]; s += L["coll"]["SYNA"]
        for n, p in self.pools.items():
            tot = sum(p["shares"].values())
            f = a["lp"].get(n, 0.0) / tot if tot > 0 else 0.0
            if p["base"] == "WETH": w += f * p["rb"]
            else: s += f * p["rb"]
            if p["quote"] == "WETH": w += f * p["rq"]
            elif p["quote"] == "SYNA": s += f * p["rq"]
        return w, s
    # ---------- block step ----------
    def step_block(self):
        a = self.blk[self.t]; b = self.blk[min(self.t + 1, STEPS - 1)]
        self.px = price_at(a["ts"])
        if self.t > 0: self.rets.append(np.log(self.px / self._pp))
        self._pp = self.px
        self.srets.append(np.log(self.spx[self.t + 1] / self.spx[self.t]) if self.t + 1 < len(self.spx) else 0.0)
        self.t += 1

def tstate(e, i):
    a = e.tr[i]; w = e.wealth(i); o = e.oracle()
    r1 = e.rets[-1] * 100 if e.rets else 0.0
    r60 = float(np.sum(e.rets[-60:])) * 100 if len(e.rets) >= 60 else 0.0
    sr60 = float(np.sum(e.srets[-60:])) * 100 if len(e.srets) >= 60 else 0.0
    debt = sum(e.val(L["cur"], L["pr"]) for L in e.debts if not L["done"] and L["bor"] == i)
    offers = [x["rate"] for x in e.offers if x["lender"] != i]
    bo = min(offers) if offers else 0.3
    _, be = e.otc_best(i)
    psu = e.pools["SYNA/USDC"]["rq"] / e.pools["SYNA/USDC"]["rb"] / o["SYNA"] - 1
    pwu = e.pools["WETH/USDC"]["rq"] / e.pools["WETH/USDC"]["rb"] / o["WETH"] - 1
    return np.array([a["usdc"] / w - 0.5, a["weth"] * o["WETH"] / w - 0.3, a["syna"] * o["SYNA"] / w - 0.2,
                     e.lp_val(i) / w, r1 * 10, e.vol20() / 100, (w - 150 * S) / (150 * S), e.t / STEPS,
                     debt / (20 * S), bo * 5, RATES[e.rate_i][0] * 5, min(2, be) / 2,
                     (o["SYNA"] / SYNA0 - 1) * 5, a["syndebt"] / (25 * S),
                     max(-5, min(5, psu)) / 5, max(-5, min(5, pwu)) / 5,
                     max(0, min(5, e.fl_opp() / S)) / 5, min(1, e.lp_val(i) / max(1e-9, w)),
                     max(-3, min(3, r60 * 10)) / 3, max(-3, min(3, sr60 * 10)) / 3], dtype=float)

def cstate(e):
    imb = sum(a["weth"] * e.px - a["usdc"] for a in e.tr) / (100 * S)
    out = sum(e.val(L["cur"], L["pr"]) for L in e.debts if not L["done"]) / (100 * S)
    return np.array([e.vol20() / 100, np.log1p(e.vol_otc + e.vol_amm + e.vol_ext) / 5,
                     (e.fund_usd() - 6.0 * S) / (20 * S), (e.cbwealth() - 10 * S) / (10 * S), e.gini() * 3, imb,
                     e.t / STEPS, out, (e.supply - e.supply0) / e.supply0, e.defaults / 10,
                     np.log1p(e.vol_amm) / 3, (e.oracle()["SYNA"] / SYNA0 - 1) * 5], dtype=float)

# trader acts: 0 hold,1 sellWETH-otc,2 buyWETH-otc,3 sellSYNA-otc,4 buySYNA-otc,5 accept-best,
# 6 amm-buy,7 amm-sell,8 ext-buy,9 ext-sell,
# 10/11 lpSU add/out,12/13 lpSW add/out,14/15 lpWU add/out,
# 16 lend,17 borrow,18 dep-peer,19 cb-dep-take,20 cb-borrow,21 invest-cb,22 mint,23 repay-syn,
# 24 burn,25 repay-all,26 FL-arb SU,27 FL-arb SW,28 FL-arb WU,29 FL-OTC,
# 30 reinvest-CB (25% free USDC),31 compound-LP (25% free USDC into deepest pool)
def do_trader(e, i, a):
    import os as _os
    _mask = _os.environ.get("MASK", "")
    if _mask and str(a) in _mask.split(","): return
    p = e.px; sp = e.oracle()["SYNA"]
    if a == 1: e.otc_post(i, "WETH", 0.002 * S, "USDC", 0.002 * S * p * 1.01)
    elif a == 2: e.otc_post(i, "USDC", 5.0 * S, "WETH", 5.0 * S / p * 0.99)
    elif a == 3: e.otc_post(i, "SYNA", 50.0 * S, "USDC", 50.0 * S * sp * 1.02)
    elif a == 4: e.otc_post(i, "USDC", 5.0 * S, "SYNA", 5.0 * S / sp * 0.98)
    elif a == 5: e.otc_accept(i)
    elif a == 6: e.amm_swap(i, "SYNA/USDC", True)
    elif a == 7: e.amm_swap(i, "SYNA/USDC", False)
    elif a == 8: e.ext_trade(i, "WETH", True)
    elif a == 9: e.ext_trade(i, "WETH", False)
    elif a == 10: e.lp_add(i, "SYNA/USDC", 0.2 * S)
    elif a == 11: e.lp_out(i, "SYNA/USDC")
    elif a == 12: e.lp_add(i, "SYNA/WETH", 0.2 * S)
    elif a == 13: e.lp_out(i, "SYNA/WETH")
    elif a == 14: e.lp_add(i, "WETH/USDC", 0.2 * S)
    elif a == 15: e.lp_out(i, "WETH/USDC")
    elif a == 16: e.lend_offer(i)
    elif a == 17: e.borrow_best(i)
    elif a == 18: e.deposit_peer(i)
    elif a == 19: e.cb_deposit(i)
    elif a == 20: e.cb_borrow(i)
    elif a == 21: e.invest_cb(i)
    elif a == 22: e.syn_mint(i)
    elif a == 23: e.syn_repay(i)
    elif a == 24: e.syn_burn(i)
    elif a == 25: e.repay_all(i)
    elif a == 26: e.fl_arb_pool(i, "SYNA/USDC")
    elif a == 27: e.fl_arb_pool(i, "SYNA/WETH")
    elif a == 28: e.fl_arb_pool(i, "WETH/USDC")
    elif a == 29: e.fl_otc(i)
    elif a == 30:  # reinvest 25% free USDC into AI CB
        _amt = e.tr[i]["usdc"] * 0.25
        if _amt > 0.01: e.invest_cb(i, _amt)
    elif a == 31:  # compound 25% free USDC as LP into deepest pool
        _amt = e.tr[i]["usdc"] * 0.25
        if _amt > 0.01:
            _bn = max(e.pools, key=lambda n: e.pool_val(n))
            e.lp_add(i, _bn, _amt)

def do_cb(e, a):
    ci, rest = divmod(a, 18); liq, rest2 = divmod(rest, 6); ri, sy = divmod(rest2, 3)
    e.comm_bps = COMM_LV[ci]; e.rate_i = ri; e.cb_hist.append((COMM_LV[ci], ri, sy))
    if liq == 1:
        e.provided += 1
        e.otc_post("cb", "USDC", 1.0 * S, "SYNA", 1.0 * S / e.oracle()["SYNA"] * 0.98)
        e.otc_post("cb", "SYNA", 10.0 * S, "USDC", 10.0 * S * e.oracle()["SYNA"] * 1.02)
        e.otc_post("cb", "USDC", 1.0 * S, "WETH", 1.0 * S / e.px * 0.99)
    if sy == 1:  # stock the fund: buy SYNA into fund inventory via internal pool
        p = e.pools["SYNA/USDC"]; u = 0.5 * S
        if e.fund["USDC"] >= u:
            e.fund["USDC"] -= u
            dx = p["rb"] * u * 0.997 / (p["rq"] + u * 0.997)
            p["rq"] += u; p["rb"] -= dx  # fee accrues to LPs (consistent with amm_swap)
            e.fund["SYNA"] += dx; e.buybacks += 1
    elif sy == 2 and e.minted_cb < 5:  # mint 2% to treasury
        m = e.supply * 0.02; e.cb["syna"] += m; e.supply += m; e.minted_cb += 1; e._dbg["cbm"] += m
        e.created += m * e.oracle()["SYNA"]

def run_episode(win, synseed, traders, cb, eps_t, eps_c, train, random_cb=False, comm_fixed=None, drift=0.0):
    e = Env(win, synseed, drift); W0 = e.world()
    S_t = [tstate(e, i) for i in range(N_TR)]; S_c = cstate(e)
    pw = [e.wealth(i) for i in range(N_TR)]; prevW = W0; prevG = e.gini()
    maxdrift = 0.0; mtm = 0.0; mtm_sys = 0.0
    act_hist = [0] * (traders[0].na if isinstance(traders, list) else 30)
    for t in range(STEPS):
        e.noise_step()  # noise FIRST: agents snipe fresh dislocations; ext_arb takes leftovers
        acts = [traders[i].act(S_t[i], eps_t) for i in range(N_TR)]
        for _a in acts:
            if 0 <= _a < len(act_hist): act_hist[_a] += 1
        for i, a in enumerate(acts): do_trader(e, i, a)
        if random_cb and comm_fixed is None:
            a_c = int(np.random.default_rng(7 + t).integers(90)); do_cb(e, a_c)
        elif comm_fixed is None:
            a_c = cb.act(S_c, eps_c); do_cb(e, a_c)
        e.ext_arb()
        eW, eS, oPx, oSp = e.expW(), e.expS(), e.px, e.spx[e.t]
        nW, nS = e.noise["weth"], e.noise["syna"]
        eA = [e.agent_exp(i) for i in range(N_TR)]
        e.expire(); e.debt_step(); e.step_block()
        dpx = e.px - oPx; dsp = e.spx[e.t] - oSp
        mtm += eW * dpx + eS * dsp
        mtm_sys += (eW - nW) * dpx + (eS - nS) * dsp
        mtm_i = [eA[i][0] * dpx + eA[i][1] * dsp for i in range(N_TR)]
        mtm_step = eW * dpx + eS * dsp
        mtm_step_sys = (eW - nW) * dpx + (eS - nS) * dsp
        e.noiseW = e.noise_wealth()
        dr = (e.world() + e.noiseW + e.cgas + e.extfees + e.extarb - W0 - e.noiseW0) - mtm - e.created + e.destroyed
        if abs(dr) > abs(maxdrift): maxdrift = dr
        S2 = [tstate(e, i) for i in range(N_TR)]; w2 = [e.wealth(i) for i in range(N_TR)]
        done = (t == STEPS - 1)
        if train:
            for i in range(N_TR):
                # differential reward x20: active P&L net of passive MTM (no inventory penalty)
                r = ((w2[i] - pw[i]) - mtm_i[i]) * 40.0 / S
                traders[i].push(S_t[i], acts[i], max(-10, min(10, r)), S2[i], done)
                if t % UPDN == 0: traders[i].upd()
            if comm_fixed is None and not random_cb:
                wW = e.world(); gN = e.gini()
                rcb = ((wW - prevW) - mtm_step_sys) / (0.1 * S) - 0.05 * e.vol20() - 2.0 * max(0.0, gN - prevG)
                cb.push(S_c, a_c, max(-10, min(10, rcb)), cstate(e), done)
                if t % UPDN == 0: cb.upd()
                prevW = wW; prevG = gN
        S_t = S2
        if comm_fixed is None: S_c = cstate(e)
        pw = w2
    now = e.blk[STEPS - 1]["ts"]
    for L in e.debts:
        if not L["done"]:
            if L["kind"] == "incb":
                due = L["pr"] * (1 + L["rate"] * (now - L["t0"]) / YR)
                if e.cb["usdc"] >= due: e.cb["usdc"] -= due; e.tr[L["lender"]]["usdc"] += due
                else: e.defaults += 1
                L["done"] = True
            else: e._settle_simpl(L, now)
    for x in e.otc:
        A = e.cb if x["who"] == "cb" else e.tr[x["who"]]
        A["lock"][x["give"]] -= x["gamt"]; A[x["give"].lower()] += x["gamt"]
    e.otc = []
    for o in e.offers:
        L = e.tr[o["lender"]]; L["usdc"] += o["amt"] if o["cur"] == "USDC" else 0.0
        if o["cur"] != "USDC": L[o["cur"].lower()] += o["amt"]
        L["esc"] -= e.val(o["cur"], o["amt"])
    dW = e.world() - W0
    edge = dW - mtm_sys + e.cgas + e.extfees + e.extarb - e.created + e.destroyed
    return dict(dW=dW, mtm=mtm_sys, edge=edge, comms=e.comms, otc=e.vol_otc, amm=e.vol_amm,
                ext=e.vol_ext, trades=e.trades, gini=e.gini(), gas=e.cgas, extf=e.extfees,
                intp2p=e.int_p2p, intcb=e.int_cb, fp2p=e.f_p2p, fcb=e.f_cb, fdep=e.f_dep,
                fincb=e.f_incb, dflt=e.defaults, liq=e.liqs, swaps=e.swaps, mints=e.mints,
                burns=e.burns, buybacks=e.buybacks, emg=e.emgmint, burned=e.burned,
                nav=e.fund_usd(), supply=e.supply, prem=(e.pools["SYNA/USDC"]["rq"] / e.pools["SYNA/USDC"]["rb"] / e.oracle()["SYNA"] - 1) * 100,
                prov=e.provided, w0=W0, w1=e.world(), cbw=e.cbwealth(), fund=e.fund_usd(), fsyn=e.fund["SYNA"],
                avgcomm=float(np.mean([c for c, _, _ in e.cb_hist])) if e.cb_hist else e.comm_bps,
                avgri=float(np.mean([r for _, r, _ in e.cb_hist])) if e.cb_hist else e.rate_i,
                maxdrift=maxdrift, px0=e.px0, px1=e.px, sp0=e.sp0, sp1=e.spx[-1],
                created=e.created, destroyed=e.destroyed,
                flvol=e.fl_vol, flpnl=e.fl_profits, flrev=e.fl_reverts, lpn=e.lp_n,
                noisepnl=e.noiseW - e.noiseW0, xarb=e.extarb,
                hist=",".join("%d:%d" % (a, c) for a, c in sorted(enumerate(act_hist), key=lambda x: -x[1])[:6]))

def save_all(tag, traders, cb):
    d = {}
    for i, t in enumerate(traders):
        for j, p in enumerate(t.net.p()): d["t%d_%d" % (i, j)] = np.array(p)
    if cb is not None:
        for j, p in enumerate(cb.net.p()): d["c_%d" % j] = np.array(p)
    np.savez(os.path.join(HERE, "nets_%s_S%d.npz" % (tag, int(S))), **d)

def load_all(tag, traders, cb):
    d = np.load(os.path.join(HERE, "nets_%s_S%d.npz" % (tag, int(S))), allow_pickle=False)
    for i, t in enumerate(traders):
        for j, p in enumerate(t.net.p()): p[:] = d["t%d_%d" % (i, j)]
        t.tgt.copy_from(t.net)
    if cb is not None:
        for j, p in enumerate(cb.net.p()): p[:] = d["c_%d" % j]
        cb.tgt.copy_from(cb.net)

def train_scenario(name, cb_seed, use_cb, random_cb=False, comm_fixed=None):
    print("--- training %s (SCALE=%g EPS=%d) ---" % (name, S, EP_TRAIN))
    traders = [DQN(20, 32, 1000 + 17 * i + 11) for i in range(N_TR)]
    cb = DQN(12, 90, 5000 + cb_seed) if use_cb else None
    hist = []
    for ep in range(EP_TRAIN):
        eps = max(0.12, 1.0 - ep / 80.0)
        m = run_episode(WINS[ep % (len(WINS)-1)], 1000 + ep, traders, cb, eps, eps, True, random_cb, comm_fixed, drift=(-0.08, 0.0, 0.08)[ep % 3])
        hist.append(dict(ep=ep, dW=m["dW"], edge=m["edge"], drift=m["maxdrift"]))
        if ep % 10 == 0 or ep == EP_TRAIN - 1:
            print("ep%d/%d eps=%.2f dW=%+.2f edge=%+.2f drift=%.2e" % (ep, EP_TRAIN, eps, m["dW"], m["edge"], m["maxdrift"]))
    save_all(name.split()[0], traders, cb)
    json.dump(hist, open(os.path.join(HERE, "hist_%s_S%d.json" % (name.split()[0], int(S))), "w"))
    m = run_episode(WINS[-1], 999, traders, cb, 0.0, 0.0, False, random_cb, comm_fixed)
    m["name"] = name
    return m

def eval_scenario(name, cb_seed, use_cb, random_cb=False, comm_fixed=None, win=None, synseed=999, drift=0.0):
    traders = [DQN(20, 32, 1000 + 17 * i + 11) for i in range(N_TR)]
    cb = DQN(12, 90, 5000 + cb_seed) if use_cb else None
    load_all(name.split()[0], traders, cb)
    m = run_episode(WINS[-1] if win is None else win, synseed, traders, cb, 0.0, 0.0, False, random_cb, comm_fixed, drift=drift)
    m["name"] = name
    return m

if os.environ.get("MODE", "full") == "evalall":
    _all = []
    for _wi in range(len(WINS)):
        for _nm, _cs, _uc, _rc, _cf in [("A NO_CB", 11, False, False, 100),
                                        ("B DQN_CB", 22, True, False, None),
                                        ("C RAND_CB", 33, False, True, None)]:
            _m = eval_scenario(_nm, _cs, _uc, _rc, _cf, win=WINS[_wi], synseed=999 + _wi)
            _m["win"] = _wi
            _all.append(_m)
            print("win%d %s dW=%+.2f edge=%+.2f gas=%.2f flpnl=%+.2f" %
                  (_wi, _m["name"], _m["dW"], _m["edge"], _m["gas"], _m["flpnl"]))
    json.dump(dict(scen=[{k: (float(v) if not isinstance(v, str) else v) for k, v in _m.items() if k != "name"} | {"name": _m["name"]} for _m in _all]),
              open(os.path.join(HERE, "results_all_S%d.json" % int(S)), "w"), indent=2)
    print("saved results_all")
    raise SystemExit

if os.environ.get("MODE", "full") == "fuzz":
    import os as _o2
    rg = np.random.default_rng(5)
    e = Env(WINS[0], 999); W0 = e.world(); mtm = 0.0
    _alog = []
    _off0 = e.phys_syna() - e.supply  # noise float offset (constant: noise never mints/burns)
    for t in range(STEPS):
        _b0 = (e.phys_syna(), e.supply)
        e.noise_step()
        _bn = (e.phys_syna(), e.supply)
        for i in range(N_TR):
            _aa = int(rg.integers(0, 32))
            _alog.append((t, i, _aa))
            import os as _o3
            if _o3.environ.get("TRACE", "") == "1":
                _pp0, _ss0 = e.phys_syna(), e.supply
                do_trader(e, i, _aa)
                _pp1, _ss1 = e.phys_syna(), e.supply
                if abs((_pp1 - _pp0) - (_ss1 - _ss0)) > 1e-9:
                    print("ACT-GAP t=%d i=%d a=%d dphys=%+.4f dsupply=%+.4f" % (t, i, _aa, _pp1 - _pp0, _ss1 - _ss0))
            else:
                do_trader(e, i, _aa)
        if _o2.environ.get("CBX", "") == "1": do_cb(e, int(rg.integers(0, 90)))
        _b1 = (e.phys_syna(), e.supply)
        e.ext_arb()
        _b2 = (e.phys_syna(), e.supply)
        eW, eS, oPx, oSp = e.expW(), e.expS(), e.px, e.spx[e.t]
        e.expire(); e.debt_step(); e.step_block()
        _b3 = (e.phys_syna(), e.supply)
        import os as _o4
        if _o4.environ.get("TRACE", "") == "1":
            _segs = [("noise", _bn, _b0), ("acts+cb", _b1, _bn), ("arb", _b2, _b1), ("tail", _b3, _b2)]
            _bad = [(n, (a[0] - b[0]) - (a[1] - b[1])) for n, a, b in _segs]
            if any(abs(d) > 1e-9 for _, d in _bad):
                print("STEP-GAP t=%d %s" % (t, " ".join("%s=%+.4f" % (n, d) for n, d in _bad)))
        e.ext_arb()
        eW, eS, oPx, oSp = e.expW(), e.expS(), e.px, e.spx[e.t]
        e.expire(); e.debt_step(); e.step_block()
        mtm += eW * (e.px - oPx) + eS * (e.spx[e.t] - oSp)
        e.noiseW = e.noise_wealth()
        dr = (e.world() + e.noiseW + e.cgas + e.extfees + e.extarb - W0 - e.noiseW0) - mtm - e.created + e.destroyed
        _ph = (e.phys_syna() - e.supply - _off0)
        if abs(_ph) > 1e-6:
            print("SUPPLY-BREAK t=%d phys=%.3f supply=%.3f off=%.3f ndebts=%d notc=%d" % (t, e.phys_syna(), e.supply, _off0, len(e.debts), len(e.otc)))
            print(" agents=%s" % ([round(a["syna"], 3) for a in e.tr],))
            print(" locks=%s cb=%s fund=%s" % ([round(a["lock"]["SYNA"], 3) for a in e.tr], round(e.cb["syna"], 3), round(e.fund["SYNA"], 3)))
            print(" debts=%s" % ([(L["kind"], L["bor"], round(L["pr"], 3), {k: round(v, 3) for k, v in L["coll"].items()}, L["done"]) for L in e.debts],))
            print(" pools=%s" % ({n: (round(p["rb"], 3), round(p["rq"], 3)) for n, p in e.pools.items()},))
            print(" otc=%s" % ([(x["who"], x["give"], round(x["gamt"], 3), x["want"], round(x["wamt"], 3)) for x in e.otc],))
            print(" actions=%s" % (_alog[-30:],))
            break
        if t % 200 == 199:
            print("t=%d drift=%+.4f world=%.2f ndebts=%d notc=%d supply=%.0f created=%.2f destroyed=%.2f emg=%.1f eb=%.0f es=%.0f bn=%.0f cbm=%.0f" % (t, dr, e.world(), len(e.debts), len(e.otc), e.supply, e.created, e.destroyed, e.emgmint, e._dbg["eb"], e._dbg["es"], e._dbg["bn"], e._dbg["cbm"]))
    print("FUZZ done")
    raise SystemExit
if os.environ.get("MODE", "full") == "unit":
    fails = 0
    def check(tag, e, w0, g0, f0, c0=0, d0=0):
        global fails
        dr = (e.world() + e.noise_wealth() + (e.cgas - g0) + (e.extfees - f0) + e.extarb - w0 - e.noiseW0) - (e.created - c0) + (e.destroyed - d0)  # no price moves here
        ok = abs(dr) < 1e-9
        if not ok: fails += 1
        print("%s drift=%.3e %s" % (tag, dr, "OK" if ok else "FAIL"))
    e = Env(WINS[0], 7); w0 = e.world()
    e.comm_bps = 100
    e.otc_post(0, "USDC", 5.0, "WETH", 5.0 / e.px * 0.99); check("otc-post", e, w0, 0, 0)
    e.otc_accept(1); check("otc-take", e, w0, 0, 0)
    e.amm_swap(2, "SYNA/USDC", True); check("swap", e, w0, 0, 0)
    e.ext_trade(3, "WETH", True); check("ext", e, w0, 0, 0)
    e.lp_add(4, "SYNA/USDC", 1.0); check("lp+", e, w0, 0, 0)
    e.lp_out(4, "SYNA/USDC"); check("lp-", e, w0, 0, 0)
    e.lend_offer(0); check("offer", e, w0, 0, 0)
    e.borrow_best(1); check("borrow", e, w0, 0, 0)
    e.deposit_peer(2); check("dep", e, w0, 0, 0)
    e.cb_borrow(3); check("cb-bor", e, w0, 0, 0)
    e.invest_cb(4); check("incb", e, w0, 0, 0)
    e.syn_mint(5); check("mint", e, w0, 0, 0)
    e.syn_repay(5); check("repay-syn", e, w0, 0, 0)
    e.syn_burn(0, 5.0); check("burn", e, w0, 0, 0)
    e.lp_add(0, "SYNA/WETH", 1.0); check("lp+SW", e, w0, 0, 0)
    e.lp_out(0, "SYNA/WETH"); check("lp-SW", e, w0, 0, 0)
    e.lp_add(1, "WETH/USDC", 1.0); check("lp+WU", e, w0, 0, 0)
    e.lp_out(1, "WETH/USDC"); check("lp-WU", e, w0, 0, 0)
    # flash-arb: force pool off-peg via REAL buys, verify exact profit extraction
    for _ in range(3):
        e.amm_swap(3, "SYNA/USDC", True)  # buys push internal SYNA price up
    _w0 = e.world(); _g0 = e.cgas; _f0 = e.extfees; _c0 = e.created; _d0 = e.destroyed
    ok = e.fl_arb_pool(2, "SYNA/USDC")
    print("fl-profitable executed=%s pnl=%.4f %s" % (ok, e.fl_profits, "OK" if ok and e.fl_profits > 0.01 * S else "FAIL"))
    if not ok or e.fl_profits <= 0.01 * S: fails += 1
    check("fl-profit", e, _w0, _g0, _f0, _c0, _d0)
    # revert case: aligned pool, tiny size edge < gas
    e2 = Env(WINS[0], 7); w02 = e2.world()
    e2.comm_bps = 100
    r = e2.fl_arb_pool(0, "WETH/USDC")
    _dr = (e2.world() + (e2.cgas) + (e2.extfees) - w02) - e2.created + e2.destroyed
    print("fl-revert returned=%s drift=%.3e %s" % (r, _dr, "OK" if abs(_dr) < 1e-9 else "FAIL"))
    if abs(_dr) >= 1e-9: fails += 1
    e2.otc_post(0, "USDC", 5.0 * S, "WETH", 5.0 * S / e2.px * 0.4)  # maker sells WETH 2.5x cheap
    ok2 = e2.fl_otc(1)
    print("fl-otc executed=%s %s" % (ok2, "OK" if ok2 else "FAIL"))
    if not ok2: fails += 1
    _dr2 = (e2.world() + (e2.cgas) + (e2.extfees) + e2.extarb - w02) - e2.created + e2.destroyed
    print("fl-otc drift=%.3e %s" % (_dr2, "OK" if abs(_dr2) < 1e-9 else "FAIL"))
    if abs(_dr2) >= 1e-9: fails += 1
    # external arb: force SU pool 5x overpriced, verify closure to +2% band, value leaves system
    e3 = Env(WINS[0], 11)
    _p = e3.pools["SYNA/USDC"]; _p["rq"] *= 5.0
    _w03 = e3.world()
    _pv0 = {n: round(e3.pool_val(n), 6) for n in e3.pools}
    print("pre-arb rb=%.4f rq=%.4f poolvals=%s" % (_p["rb"], _p["rq"], _pv0))
    e3.ext_arb()
    _pv1 = {n: round(e3.pool_val(n), 6) for n in e3.pools}
    print("post-arb rb=%.4f rq=%.4f poolvals=%s" % (_p["rb"], _p["rq"], _pv1))
    # external arb: force SU pool 5x overpriced. Micro-scale extraction < $0.02 searcher
    # threshold => rational SKIP is correct; normal scale => closure to +2%.
    _px1 = _p["rq"] / _p["rb"] / e3.oracle()["SYNA"] - 1
    _dr3 = (e3.world() + e3.noise_wealth() + e3.cgas + e3.extfees + e3.extarb - _w03 - e3.noiseW0)
    _closed = abs(_px1 - 0.02) < 0.005 and e3.extarb > 0
    _skipped = abs(_px1 - 4.0) < 0.01 and e3.extarb == 0.0
    print("extarb prem=%+.3f extarb=%.4f drift=%.3e %s" % (_px1, e3.extarb, _dr3, "OK" if ((_closed or _skipped) and abs(_dr3) < 1e-9) else "FAIL"))
    if not ((_closed or _skipped) and abs(_dr3) < 1e-9): fails += 1
    # ext_arb on ALL pools from genesis (SW/WU start off-peg): must conserve exactly
    e4 = Env(WINS[0], 13)
    _w04 = e4.world()
    for _k in range(5):
        e4.ext_arb()
    _dr4 = (e4.world() + e4.noise_wealth() + e4.cgas + e4.extfees + e4.extarb - _w04 - e4.noiseW0)
    _pm = {n: round(e4.pools[n]["rq"] / e4.pools[n]["rb"] / (e4.oracle()[e4.pools[n]["base"]] / e4.oracle()[e4.pools[n]["quote"]]) - 1, 4) for n in e4.pools}
    print("extarb-all prems=%s extarb=%.4f drift=%.3e %s" % (_pm, e4.extarb, _dr4, "OK" if abs(_dr4) < 1e-9 else "FAIL"))
    if abs(_dr4) >= 1e-9: fails += 1
    # noise_step x200 isolated
    e5 = Env(WINS[0], 17)
    _w05 = e5.world()
    for _k in range(200):
        e5.noise_step()
    _dr5 = (e5.world() + e5.noise_wealth() + e5.cgas + e5.extfees + e5.extarb - _w05 - e5.noiseW0)
    print("noise200 drift=%.3e %s" % (_dr5, "OK" if abs(_dr5) < 1e-9 else "FAIL"))
    if abs(_dr5) >= 1e-9: fails += 1
    # lp_add sweep across pool imbalances and balances (the t2-compound suspect)
    import itertools as _it
    _bad = 0
    for _rb, _rq, _au, _as in _it.product([0.5, 2.0, 5.0, 20.0], [0.05, 0.5, 2.0], [0.5, 2.0, 10.0], [1.0, 5.0, 30.0]):
        _e = Env(WINS[0], 23)
        _p = _e.pools["SYNA/USDC"]; _p["rb"], _p["rq"] = _rb, _rq
        _a = _e.tr[0]; _a["usdc"], _a["syna"] = _au, _as
        _w = _e.world() + _e.noise_wealth()
        _ok = _e.lp_add(0, "SYNA/USDC", 0.2 * _au)
        _dd = (_e.world() + _e.noise_wealth() + _e.cgas + _e.extfees + _e.extarb - _w)
        if abs(_dd) > 1e-9:
            _bad += 1
            if _bad < 4: print("lp-sweep FAIL rb=%.2f rq=%.3f usdc=%.2f syna=%.1f ok=%s drift=%.3e" % (_rb, _rq, _au, _as, _ok, _dd))
    print("lp-sweep %s (%d states)" % ("OK" if _bad == 0 else "FAIL(%d)" % _bad, 4 * 3 * 3 * 3))
    if _bad: fails += 1
    # do_cb buyback x10 + mint x5 isolated (with phys-vs-supply invariant)
    e6 = Env(WINS[0], 19)
    _w06 = e6.world(); _o06 = e6.phys_syna() - e6.supply
    for _k in range(10):
        e6.comm_bps = 100
        do_cb(e6, 1 * 9 + 1 * 3 + 1)  # liq=1, rate=1, syna=1 (provide+buyback)
    for _k in range(5):
        do_cb(e6, 4 * 9 + 2 * 3 + 2)  # comm=4, liq=2?, rate=2, syna=2 (mint)
    _dr6 = (e6.world() + e6.noise_wealth() + e6.cgas + e6.extfees + e6.extarb - _w06 - e6.noiseW0) - e6.created + e6.destroyed
    _ph6 = (e6.phys_syna() - e6.supply - _o06)
    print("cb10 drift=%.3e physgap=%.3e %s" % (_dr6, _ph6, "OK" if abs(_dr6) < 1e-9 and abs(_ph6) < 1e-9 else "FAIL"))
    if abs(_dr6) >= 1e-9 or abs(_ph6) >= 1e-9: fails += 1
    print("UNIT " + ("PASS" if fails == 0 else "FAIL(%d)" % fails))
    raise SystemExit
MODE = os.environ.get("MODE", "full")
if MODE == "demo":
    # scripted OPTIMAL FL+LP policy (upper bound): snipe dislocations first-look, LP SU once, exit at end
    e = Env(WINS[0], 999); e.comm_bps = 10; W0 = e.world()
    e.noiseW0 = e.noise_wealth(); mtm = 0.0; maxdrift = 0.0
    for t in range(STEPS):
        for i in range(N_TR):
            if e.fl_opp() > 0.02:
                for _n in ("SYNA/USDC", "SYNA/WETH", "WETH/USDC"):
                    e.fl_arb_pool(i, _n)
            if t < 6: e.lp_add(i, "SYNA/USDC", 0.2 * S)
            if t == 1100: e.lp_out(i, "SYNA/USDC", frac=1.0)
        e.noise_step(); e.ext_arb()
        oW, oS, oPx, oSp = e.expW(), e.expS(), e.px, e.spx[e.t]
        e.expire(); e.debt_step(); e.step_block()
        mtm += oW * (e.px - oPx) + oS * (e.spx[e.t] - oSp)
        e.noiseW = e.noise_wealth()
        dr = (e.world() + e.noiseW + e.cgas + e.extfees + e.extarb - W0 - e.noiseW0) - mtm - e.created + e.destroyed
        if abs(dr) > abs(maxdrift): maxdrift = dr
    dW = e.world() - W0
    print("DEMO OPTIMAL-FL+LP: dW=%+.2f = MTM%+.2f + edge%+.2f - gas%.2f - extfee%.2f + extarb-out %.2f" %
          (dW, mtm, dW - mtm + e.cgas + e.extfees - e.created + e.destroyed, e.cgas, e.extfees, e.extarb))
    print("  FL vol=%.0f pnl=%+.2f reverts=%d LPops=%d premSU=%+.1f%% noise=%+.2f maxdrift=%.2e" %
          (e.fl_vol, e.fl_profits, e.fl_reverts, e.lp_n,
           (e.pools["SYNA/USDC"]["rq"] / e.pools["SYNA/USDC"]["rb"] / e.oracle()["SYNA"] - 1) * 100,
           e.noiseW - e.noiseW0, maxdrift))
    raise SystemExit
if MODE == "train":
    _sc = os.environ.get("SCEN", "A")
    _cfg = dict(A=(11, False, False, 100), B=(22, True, False, None), C=(33, False, True, None))[_sc]
    _trs, _cb, _h = None, None, None
    _name = {"A": "A NO_CB", "B": "B DQN_CB", "C": "C RAND_CB"}[_sc]
    _traders = [DQN(20, 32, 1000 + 17 * i + 11) for i in range(N_TR)]
    _cb = DQN(12, 90, 5000 + _cfg[0]) if _cfg[1] else None
    _off = int(os.environ.get("EP_OFFSET", "0"))
    if os.environ.get("RESUME", "") == "1":
        try:
            load_all(_sc, _traders, _cb)
            print("resumed nets_%s from ep %d" % (_sc, _off))
        except Exception as _ex:
            print("no checkpoint: %s" % str(_ex)[:120])
    print("--- training %s (SCALE=%g EPS=%d+%d) ---" % (_name, S, _off, EP_TRAIN))
    _hist = []
    for _ep in range(EP_TRAIN):
        _eps = max(0.12, 1.0 - (_ep + _off) / 80.0)
        _m = run_episode(WINS[(_ep + _off) % (len(WINS)-1)], 1000 + _ep + _off, _traders, _cb, _eps, _eps, True, _cfg[2], _cfg[3], drift=(-0.08, 0.0, 0.08)[(_ep + _off) % 3])
        _hist.append(dict(ep=_ep + _off, dW=_m["dW"], edge=_m["edge"], drift=_m["maxdrift"]))
        if _ep % 10 == 0 or _ep == EP_TRAIN - 1:
            print("ep%d/%d eps=%.2f dW=%+.2f edge=%+.2f drift=%.2e" % (_ep + _off, _off + EP_TRAIN, _eps, _m["dW"], _m["edge"], _m["maxdrift"]))
    save_all(_sc, _traders, _cb)
    _hp = os.path.join(HERE, "hist_%s_S%d.json" % (_sc, int(S)))
    _old = []
    if os.environ.get("RESUME", "") == "1":
        try: _old = json.load(open(_hp))
        except Exception: _old = []
    json.dump(_old + _hist, open(_hp, "w"))
    print("saved nets_%s" % _sc)
    raise SystemExit
def _eprint(res, tag="results_syna"):
    print("EVAL REAL blocks %d..%d WETH $%.2f->$%.2f SYNA $%.3f->$%.3f SCALE=%g" %
          (WINS[-1][0]["n"], WINS[-1][-1]["n"], res[0]["px0"], res[0]["px1"], res[0]["sp0"], res[0]["sp1"], S))
    for m in res:
        print("%s\n  dW=%+.3f = MTM%+.3f + edge%+.3f - gas%.3f - extfee%.3f | TR=%d OTC=%.0f AMM=%.0f EXT=%.0f" %
              (m["name"], m["dW"], m["mtm"], m["edge"], m["gas"], m["extf"], m["trades"], m["otc"], m["amm"], m["ext"]))
        print("  fees=%.3f intP2P=%.4f intCB=%.4f fP2P=%.0f fCB=%.0f fDep=%.0f fInCB=%.0f dflt=%d liq=%d" %
              (m["comms"], m["intp2p"], m["intcb"], m["fp2p"], m["fcb"], m["fdep"], m["fincb"], m["dflt"], m["liq"]))
    print("  mints=%d burns=%d buyback=%d emgMint=%.1f supply=%.0f prem=%+.1f%% fund=%.2f gini=%.3f CB:c=%.0f r=%.1f treas=%.2f seign=%+.2f destr=%+.2f" %
          (m["mints"], m["burns"], m["buybacks"], m["emg"], m["supply"], m["prem"], m["fund"], m["gini"], m["avgcomm"], m["avgri"], m["cbw"], m["created"], m["destroyed"]))
    print("  FLASH vol=%.0f pnl=%+.2f reverts=%d | LP ops=%d | noise=%+.2f | extarb=%.2f | acthist=%s" % (m["flvol"], m["flpnl"], m["flrev"], m["lpn"], m["noisepnl"], m["xarb"], m["hist"]))
    b = res[1]; a = res[0]
    print("CB effect vs NO_CB: dW %+.3f (edge %+.3f vs %+.3f)" % (b["dW"] - a["dW"], b["edge"], a["edge"]))
    json.dump(dict(scen=[{k: (float(v) if not isinstance(v, str) else v) for k, v in m.items() if k != "name"} | {"name": m["name"]} for m in res]),
              open(os.path.join(HERE, tag + "_S%d.json" % int(S)), "w"), indent=2)
    print("saved " + tag)

if MODE == "eval":
    res = []
    for _dr, _rn in [(0.0, "flat"), (-0.08, "bear"), (0.08, "bull")]:
        for _nm, _cs, _uc, _rc, _cf in [("A NO_CB", 11, False, False, 100),
                                        ("B DQN_CB", 22, True, False, None),
                                        ("C RAND_CB", 33, False, True, None)]:
            _m = eval_scenario(_nm, _cs, _uc, _rc, _cf, drift=_dr)
            _m["name"] = "%s [%s]" % (_nm, _rn)
            res.append(_m)
    print("=" * 78)
    _eprint(res)
    raise SystemExit
if MODE == "full":
    res = [train_scenario("A NO_CB", 11, False, comm_fixed=100),
           train_scenario("B DQN_CB", 22, True),
           train_scenario("C RAND_CB", 33, False, random_cb=True)]
    print("=" * 78)
    _eprint(res)
