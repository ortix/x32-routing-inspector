// scn.js — Behringer X32 / Midas M32 scene-file (.scn) parser + AES50 flow analyzer.
// Pure business logic. No DOM. Exported for the Design Component logic class.

// ---------- low-level tokenizer ----------
function tokenize(rest) {
  const out = [];
  let i = 0;
  while (i < rest.length) {
    const c = rest[i];
    if (c === ' ' || c === '\t') { i++; continue; }
    if (c === '"') {
      let j = i + 1, s = '';
      while (j < rest.length && rest[j] !== '"') { s += rest[j]; j++; }
      out.push(s);
      i = j + 1;
    } else {
      let j = i, s = '';
      while (j < rest.length && rest[j] !== ' ' && rest[j] !== '\t') { s += rest[j]; j++; }
      out.push(s);
      i = j;
    }
  }
  return out;
}

// ---------- source-index resolvers ----------
// Global input source numbering used by /config/userrout/in.
// Verified against real scenes: AES50-A starts at 33 (so A15 = 47), AES50-B at
// 81, Card at 129 — e.g. backing-track/click channels patched to value 129 land
// on Card 1, and a vocal patched to 47 lands on AES50-A 15.
export function resolveGlobalIn(n) {
  n = +n;
  if (!n || n === 0) return { kind: 'OFF', n: 0, label: '—', short: '—' };
  if (n <= 32) return { kind: 'Local', n, label: 'Local ' + n, short: 'L' + n };
  if (n <= 80) return { kind: 'AES50A', n: n - 32, label: 'AES50-A ' + (n - 32), short: 'A' + (n - 32) };
  if (n <= 128) return { kind: 'AES50B', n: n - 80, label: 'AES50-B ' + (n - 80), short: 'B' + (n - 80) };
  return { kind: 'Card', n: n - 128, label: 'Card ' + (n - 128), short: 'C' + (n - 128) };
}

// Global output source numbering used by /config/userrout/out (and AES50 OUT taps).
export function resolveGlobalOut(n) {
  n = +n;
  if (!n || n === 0) return { kind: 'OFF', n: 0, label: '—', short: '—' };
  if (n <= 16) return { kind: 'MixBus', n, label: 'Out ' + n, short: 'OUT' + n };
  if (n <= 32) return { kind: 'MixBus', n, label: 'Out ' + n, short: 'OUT' + n };
  // P16 etc fall through — keep generic
  return { kind: 'Sig', n, label: 'Sig ' + n, short: 'S' + n };
}

// Source feeding a USER OUTPUT (/config/userrout/out value, 0..208).
// Per the X32/M32 OSC spec the input portion (1..160) is the SAME signal
// enumeration as user inputs, so a user-output carrying value 33 taps AES50-A 1
// — i.e. it forwards the stage box, exactly like a direct A1-8 send block. Values
// 161..208 are console-generated outputs (aux/bus/P16/monitor), never a shared
// physical input, so they get distinct kinds that won't false-match a stage origin.
export function resolveUserOutSource(n) {
  n = +n;
  if (!n || n === 0) return { kind: 'OFF', n: 0, label: '—', short: '—' };
  if (n <= 32) return { kind: 'Local', n, label: 'Local ' + n, short: 'L' + n };
  if (n <= 80) return { kind: 'AES50A', n: n - 32, label: 'AES50-A ' + (n - 32), short: 'A' + (n - 32) };
  if (n <= 128) return { kind: 'AES50B', n: n - 80, label: 'AES50-B ' + (n - 80), short: 'B' + (n - 80) };
  if (n <= 160) return { kind: 'Card', n: n - 128, label: 'Card ' + (n - 128), short: 'C' + (n - 128) };
  if (n <= 166) return { kind: 'AuxIn', n: n - 160, label: 'Aux In ' + (n - 160), short: 'AUX' + (n - 160) };
  if (n <= 168) return { kind: 'TB', n: n - 166, label: 'Talkback ' + (n - 166), short: 'TB' + (n - 166) };
  if (n <= 184) return { kind: 'OutTap', n: n - 168, label: 'Out ' + (n - 168), short: 'OUT' + (n - 168) };
  if (n <= 200) return { kind: 'P16', n: n - 184, label: 'P16 ' + (n - 184), short: 'P16-' + (n - 184) };
  if (n <= 206) return { kind: 'AuxOut', n: n - 200, label: 'AUX ' + (n - 200), short: 'AUXo' + (n - 200) };
  return { kind: 'Monitor', n: n - 206, label: 'Monitor ' + (n === 207 ? 'L' : 'R'), short: 'MON' + (n === 207 ? 'L' : 'R') };
}

// Parse a routing token like 'AN1-8','A9-16','UIN17-24','OUT1-8','P161-8','AUX/TB'.
function parseRouteToken(tok) {
  if (!tok) return null;
  if (tok.indexOf('/') >= 0) {
    // AUX/TB, AUX/CR
    return { prefix: tok, start: 0, special: true };
  }
  const m = tok.match(/^([A-Z]+)(\d+)-(\d+)$/);
  if (m) return { prefix: m[1], start: +m[2], end: +m[3], special: false };
  // P161-8 style: prefix P16, start 1
  const m2 = tok.match(/^(P16|UOUT|UIN|CARD|AES)(\d+)-(\d+)$/);
  if (m2) return { prefix: m2[1], start: +m2[2], end: +m2[3], special: false };
  return { prefix: tok, start: 0, special: true };
}

const PREFIX_KIND = {
  AN: 'Local', A: 'AES50A', B: 'AES50B', CARD: 'Card', UIN: 'UserIn',
  AUX: 'Aux', OUT: 'MixBus', UOUT: 'UserOut', P16: 'P16',
};

// ---------- main parser ----------
export function parseScene(text, fileName) {
  const raw = {};
  const lines = text.split(/\r?\n/);
  let sceneName = fileName || 'Scene';
  for (const line of lines) {
    if (line[0] === '#') {
      const t = tokenize(line.replace(/^#[^#]*#/, ''));
      if (t[0]) sceneName = t[0];
      continue;
    }
    if (line[0] !== '/') continue;
    const sp = line.indexOf(' ');
    const path = sp < 0 ? line : line.slice(0, sp);
    const rest = sp < 0 ? '' : line.slice(sp + 1);
    raw[path] = rest;
  }
  const tk = (p) => tokenize(raw[p] || '');

  // config routing
  const routing = {
    IN: tk('/config/routing/IN'),
    AES50A: tk('/config/routing/AES50A'),
    AES50B: tk('/config/routing/AES50B'),
    CARD: tk('/config/routing/CARD'),
    OUT: tk('/config/routing/OUT'),
    PLAY: tk('/config/routing/PLAY'),
  };
  const userrout = {
    in: tk('/config/userrout/in').map(Number),
    out: tk('/config/userrout/out').map(Number),
  };

  // channels 1..32
  const channels = [];
  for (let i = 1; i <= 32; i++) {
    const id = String(i).padStart(2, '0');
    const cfg = tk('/ch/' + id + '/config');
    if (!raw['/ch/' + id + '/config']) continue;
    const name = cfg[0] || '';
    const icon = cfg[1] || '';
    const color = cfg[2] || '';
    const source = +cfg[3] || 0;
    // main / LR
    const mix = tk('/ch/' + id + '/mix');
    const lrOn = mix[2] === 'ON';
    const fader = mix[1] || '-oo';
    const muted = mix[0] !== 'ON';
    // bus sends (odd indices 01..15 carry level; pairs are stereo links)
    const busSends = [];
    for (let b = 1; b <= 16; b++) {
      const bid = String(b).padStart(2, '0');
      const mb = tk('/ch/' + id + '/mix/' + bid);
      if (!mb.length) continue;
      const on = mb[0] === 'ON';
      const lvl = mb[1] || '-oo';
      busSends.push({ bus: b, on, level: lvl, active: on && lvl !== '-oo' });
    }
    channels.push({ idx: i, id, name, icon, color, source, lrOn, fader, muted, busSends });
  }

  // aux returns 1..8
  const auxin = [];
  for (let i = 1; i <= 8; i++) {
    const id = String(i).padStart(2, '0');
    if (!raw['/auxin/' + id + '/config']) continue;
    const cfg = tk('/auxin/' + id + '/config');
    auxin.push({ idx: i, id, name: cfg[0] || '', color: cfg[2] || '', source: +cfg[3] || 0 });
  }

  // outputs
  const outMain = [];
  for (let i = 1; i <= 16; i++) {
    const id = String(i).padStart(2, '0');
    const t = tk('/outputs/main/' + id);
    if (!t.length) continue;
    outMain.push({ idx: i, src: +t[0] || 0, tap: t[1] || '', invert: t[2] === 'ON' });
  }

  return {
    fileName, sceneName, raw, routing, userrout, channels, auxin, outMain,
  };
}

// Resolve an input SLOT (1..32) of a console to its physical origin, walking the
// IN routing block and the user-input patch when the block is UIN.
export function resolveSlot(con, slot) {
  if (!slot || slot < 1 || slot > 32) return { kind: 'OFF', label: '—', short: '—' };
  const block = Math.floor((slot - 1) / 8);   // 0..3
  const offset = (slot - 1) % 8;
  const tok = con.routing.IN[block];
  const pt = parseRouteToken(tok);
  if (!pt) return { kind: '?', label: tok || '?', short: '?' };
  if (pt.prefix === 'UIN') {
    const uin = pt.start + offset;             // user-in slot 1..32
    const g = con.userrout.in[uin - 1];
    const r = resolveGlobalIn(g);
    return Object.assign({ via: 'UserIn ' + uin }, r);
  }
  const kind = PREFIX_KIND[pt.prefix] || pt.prefix;
  const port = pt.start + offset;
  const shortPrefix = { Local: 'L', AES50A: 'A', AES50B: 'B', Card: 'C', Aux: 'AUX' }[kind] || pt.prefix;
  return { kind, n: port, label: kind + ' ' + port, short: shortPrefix + port };
}

// What signal feeds AES50 output port (1..48) on bus 'A' or 'B' of this console.
export function resolveAesSend(con, busAB, port) {
  const blocks = busAB === 'A' ? con.routing.AES50A : con.routing.AES50B;
  const block = Math.floor((port - 1) / 8);
  const offset = (port - 1) % 8;
  const tok = blocks[block];
  const pt = parseRouteToken(tok);
  if (!pt || pt.special) return { kind: tok || 'OFF', label: tok || '—', short: tok || '—', tok };
  const idx = pt.start + offset;
  // A USER OUTPUT block is an indirection: the actual signal it carries is set by
  // the /config/userrout/out patch. Chase it (mirrors how resolveSlot follows
  // userrout.in for UIN blocks) so a stage box forwarded via the user-out matrix
  // resolves to its real origin instead of an opaque "UserOut N".
  if (pt.prefix === 'UOUT') {
    const g = con.userrout.out[idx - 1];
    const r = resolveUserOutSource(g);
    return Object.assign({ tok, via: 'UserOut ' + idx }, r);
  }
  const kind = PREFIX_KIND[pt.prefix] || pt.prefix;
  const map = {
    MixBus: { label: 'Out ' + idx, short: 'OUT' + idx },
    UserOut: { label: 'UserOut ' + idx, short: 'UO' + idx },
    P16: { label: 'P16 ' + idx, short: 'P16-' + idx },
    AES50A: { label: 'AES50-A in ' + idx, short: 'A' + idx },
    AES50B: { label: 'AES50-B in ' + idx, short: 'B' + idx },
    Local: { label: 'Local ' + idx, short: 'L' + idx },
    Card: { label: 'Card ' + idx, short: 'C' + idx },
  }[kind] || { label: kind + ' ' + idx, short: kind + idx };
  return Object.assign({ kind, n: idx, tok }, map);
}

// Buses a channel feeds (active sends only), plus LR.
export function channelDestinations(ch) {
  const d = [];
  if (ch.lrOn) d.push({ type: 'LR', label: 'Main LR' });
  for (const s of ch.busSends) if (s.active) d.push({ type: 'Bus', n: s.bus, label: 'Bus ' + s.bus, level: s.level });
  return d;
}

// ============================================================================
//  AES50 LINK MODEL
//  Topology: the MONITOR console owns the stage box on its AES50-A inputs.
//  It passes signals onto its AES50-B outputs, which are cabled to the FOH
//  console's AES50-A inputs.  So:  FOH AES50-A in[p]  ===  MON AES50-B out[p].
//  A "canonical origin" lets a MON channel and a FOH channel be compared even
//  when they listen via totally different routing paths or carry different names.
// ============================================================================

// Canonical origin = a stable identity for the physical signal a channel listens
// to, expressed in stage-box terms so both desks share a vocabulary.
export function canonicalOrigin(role, con, link) {
  // role: 'MON' | 'FOH'.  link = { mon, foh }.
  return function (ch) {
    const r = resolveSlot(con, ch.source);
    if (role === 'MON') {
      if (r.kind === 'AES50A')
        return { key: 'STAGE:' + r.n, kind: 'Stage', port: r.n, label: 'Stage box ' + r.n, short: 'STG' + r.n, slotRes: r };
      if (r.kind === 'Local')
        return { key: 'MONLOCAL:' + r.n, kind: 'MonLocal', port: r.n, label: 'Monitor local ' + r.n, short: 'mLOC' + r.n, slotRes: r };
      if (r.kind === 'AES50B')
        return { key: 'FROMFOH:' + r.n, kind: 'FromFOH', port: r.n, label: 'From FOH / playback (B' + r.n + ')', short: 'B' + r.n, slotRes: r };
      if (r.kind === 'Card')
        return { key: 'MONCARD:' + r.n, kind: 'MonCard', port: r.n, label: 'Monitor card ' + r.n, short: 'mC' + r.n, slotRes: r };
      return { key: r.kind + ':' + (r.n || 0), kind: r.kind, port: r.n, label: r.label, short: r.short, slotRes: r };
    }
    // FOH
    if (r.kind === 'AES50A') {
      const s = resolveAesSend(link.mon, 'B', r.n);     // what the monitor actually puts there
      if (s.kind === 'AES50A')
        return { key: 'STAGE:' + s.n, kind: 'Stage', port: s.n, label: 'Stage box ' + s.n, short: 'STG' + s.n, slotRes: r, linkPort: r.n, monSend: s };
      if (s.kind === 'Local')
        return { key: 'MONLOCAL:' + s.n, kind: 'MonLocal', port: s.n, label: 'Monitor local ' + s.n, short: 'mLOC' + s.n, slotRes: r, linkPort: r.n, monSend: s };
      if (s.kind === 'Card')
        return { key: 'MONCARD:' + s.n, kind: 'MonCard', port: s.n, label: 'Monitor card ' + s.n, short: 'mC' + s.n, slotRes: r, linkPort: r.n, monSend: s };
      return { key: 'LINK:' + s.short, kind: s.kind, label: s.label, short: s.short, slotRes: r, linkPort: r.n, monSend: s };
    }
    if (r.kind === 'Local')
      return { key: 'FOHLOCAL:' + r.n, kind: 'FohLocal', port: r.n, label: 'FOH local ' + r.n, short: 'fLOC' + r.n, slotRes: r };
    return { key: r.kind + ':' + (r.n || 0), kind: r.kind, port: r.n, label: r.label, short: r.short, slotRes: r };
  };
}

// Build a human-readable signal path (array of {layer,label,detail}) for a channel.
export function channelFlow(role, con, link, ch) {
  const origin = canonicalOrigin(role, con, link)(ch);
  const r = origin.slotRes;
  const block = Math.floor((ch.source - 1) / 8);
  const inTok = ch.source >= 1 ? con.routing.IN[block] : '—';
  const steps = [];
  if (role === 'MON') {
    steps.push({ layer: 'origin', label: origin.label, detail: origin.kind === 'Stage' ? 'physical input on the shared stage box' : origin.kind === 'MonLocal' ? 'local input on the monitor console — forwarded to FOH over the AES50 cable' : r.label });
    if (origin.kind === 'Stage') steps.push({ layer: 'aes', label: 'AES50-A in ' + origin.port, detail: 'monitor receives stage box here' });
    steps.push({ layer: 'patch', label: 'IN ' + inTok + (r.via ? ' · ' + r.via : ''), detail: 'input slot ' + ch.source });
    steps.push({ layer: 'channel', label: 'Ch ' + ch.id + (ch.name ? ' · ' + ch.name : ''), detail: 'monitor channel' });
  } else {
    steps.push({ layer: 'origin', label: origin.label, detail: origin.kind === 'Stage' ? 'physical input on the shared stage box' : origin.kind === 'MonLocal' ? 'plugged into the monitor’s local input — forwarded to FOH across the AES50 cable' : origin.kind === 'FohLocal' ? 'local XLR on the FOH console — independent of the stage box' : (origin.monSend ? origin.monSend.label : r.label) });
    if (origin.linkPort) {
      steps.push({ layer: 'aes', label: 'MON AES50-B out ' + origin.linkPort, detail: 'monitor sends "' + (origin.monSend ? origin.monSend.tok : '?') + '" here' });
      steps.push({ layer: 'link', label: 'AES50 cable  B→A', detail: 'monitor B  →  FOH A' });
      steps.push({ layer: 'aes', label: 'FOH AES50-A in ' + origin.linkPort, detail: 'FOH receives here' });
    }
    steps.push({ layer: 'patch', label: 'IN ' + inTok + (r.via ? ' · ' + r.via : ''), detail: 'input slot ' + ch.source });
    steps.push({ layer: 'channel', label: 'Ch ' + ch.id + (ch.name ? ' · ' + ch.name : ''), detail: 'FOH channel' });
  }
  return { origin, steps, destinations: channelDestinations(ch), inTok };
}

// Pretty label for a canonical key.
function keyLabel(key) {
  return key.replace('STAGE:', 'stage box ').replace('MONLOCAL:', 'monitor local ').replace('MONCARD:', 'monitor card ').replace('FOHLOCAL:', 'FOH local ');
}

// Full analysis of the pair: per-channel origins, what the single AES50 cable
// actually carries, and real routing issues.
//
// The ONE cable (monitor AES50-B → FOH AES50-A) carries, per the monitor's B
// send blocks, BOTH the stage box (A passthrough) AND the monitor's own local
// inputs (AN passthrough) AND card/aux. So a FOH channel that resolves to a
// "monitor local" input is a perfectly valid, intended path — not an error.
export function analyzeLink(mon, foh) {
  const link = { mon, foh };
  const monOrigin = canonicalOrigin('MON', mon, link);
  const fohOrigin = canonicalOrigin('FOH', foh, link);

  const monCh = mon.channels.map((ch) => ({ ch, o: monOrigin(ch) }));
  const fohCh = foh.channels.map((ch) => ({ ch, o: fohOrigin(ch) }));

  const fohByKey = new Map();
  for (const x of fohCh) { if (!fohByKey.has(x.o.key)) fohByKey.set(x.o.key, []); fohByKey.get(x.o.key).push(x); }
  const monByKey = new Map();
  for (const x of monCh) { if (!monByKey.has(x.o.key)) monByKey.set(x.o.key, []); monByKey.get(x.o.key).push(x); }

  // What the monitor places on its AES50-B send (the cable to FOH), per port.
  const bSend = [];
  const forwarded = new Map();   // canonical key -> first port carrying it
  for (let q = 1; q <= 48; q++) {
    const s = resolveAesSend(mon, 'B', q);
    let key = null, kind = s.kind;
    if (s.kind === 'AES50A') { key = 'STAGE:' + s.n; kind = 'Stage'; }
    else if (s.kind === 'Local') { key = 'MONLOCAL:' + s.n; kind = 'MonLocal'; }
    else if (s.kind === 'Card') { key = 'MONCARD:' + s.n; kind = 'MonCard'; }
    else if (s.kind && s.kind !== 'OFF' && s.tok) { key = 'LINK:' + s.short; }
    bSend.push({ port: q, key, kind, label: s.label, raw: s });
    if (key && !forwarded.has(key)) forwarded.set(key, q);
  }

  const issues = [];
  const used = (ch) => ch.name && ch.name.trim() !== '';
  const ch2 = (ch) => ch.id + (ch.name ? ' "' + ch.name + '"' : '');

  // ERROR — FOH channel listening to an AES50 port the monitor sends nothing on.
  for (const { ch, o } of fohCh) {
    if (!used(ch)) continue;
    if (o.linkPort) {
      const b = bSend[o.linkPort - 1];
      if (!b || !b.key) issues.push({
        type: 'silence', sev: 'error', side: 'FOH', ref: ch.idx,
        title: 'FOH "' + ch.name + '" receives nothing',
        detail: 'FOH Ch ' + ch.id + ' reads AES50-A ' + o.linkPort + ', but the monitor sends nothing on that port of the cable. This channel is silent.',
      });
    }
  }

  // WARN — monitor channel whose source the cable does NOT carry → can't reach FOH.
  for (const { ch, o } of monCh) {
    if (!used(ch)) continue;
    if ((o.kind === 'Stage' || o.kind === 'MonLocal' || o.kind === 'MonCard') && !forwarded.has(o.key)) {
      issues.push({
        type: 'notforwarded', sev: 'warn', side: 'MON', ref: ch.idx,
        title: '"' + ch.name + '" is not carried to FOH',
        detail: 'Monitor Ch ' + ch.id + ' uses ' + o.label + ', which is not on any AES50-B send block. It physically cannot reach FOH over the cable. (Fine if it is a monitor-only source.)',
      });
    }
  }

  // WARN — same physical stage input feeding 2+ named channels on one desk.
  for (const [list, side] of [[monByKey, 'MON'], [fohByKey, 'FOH']]) {
    for (const [key, arr] of list) {
      if (!key.startsWith('STAGE:')) continue;
      const named = arr.filter((x) => used(x.ch));
      if (named.length >= 2) issues.push({
        type: 'alias', sev: 'warn', side, ref: named[0].ch.idx,
        title: side + ': ' + named.length + ' channels share ' + keyLabel(key),
        detail: side + ' channels ' + named.map((x) => ch2(x.ch)).join(', ') + ' all read ' + keyLabel(key) + '. Could be an intentional double-patch (parallel processing) — or a stale user-input patch pointing two channels at one input. Worth a look.',
      });
    }
  }

  // INFO — a forwarded source used on the monitor but not picked up at FOH.
  for (const [key, arr] of monByKey) {
    if (!(key.startsWith('STAGE:') || key.startsWith('MONLOCAL:'))) continue;
    if (!forwarded.has(key) || fohByKey.has(key)) continue;
    const named = arr.filter((x) => used(x.ch));
    if (!named.length) continue;
    issues.push({
      type: 'unused', sev: 'info', side: 'MON', ref: named[0].ch.idx,
      title: '"' + named[0].ch.name + '" is on the cable but unused at FOH',
      detail: named[0].ch.name + ' (' + keyLabel(key) + ') is carried across AES50, but no FOH channel is patched to it. Add it at FOH if it belongs in the house mix.',
    });
  }

  // INFO — same forwarded source, different names on each desk (linkable).
  const nameMismatch = [];
  const seenPair = new Set();
  for (const [key, mlist] of monByKey) {
    if (!(key.startsWith('STAGE:') || key.startsWith('MONLOCAL:') || key.startsWith('MONCARD:'))) continue;
    const flist = fohByKey.get(key);
    if (!flist) continue;
    for (const m of mlist) for (const f of flist) {
      if (!used(m.ch) || !used(f.ch)) continue;
      const a = m.ch.name.trim().toUpperCase().replace(/\s+/g, '');
      const b = f.ch.name.trim().toUpperCase().replace(/\s+/g, '');
      if (a === b) continue;
      const pk = m.ch.idx + '>' + f.ch.idx;
      if (seenPair.has(pk)) continue;
      seenPair.add(pk);
      nameMismatch.push({
        type: 'namematch', sev: 'info', key, monRef: m.ch.idx, fohRef: f.ch.idx,
        title: 'Same input, different names',
        detail: 'Monitor "' + m.ch.name + '" (Ch ' + m.ch.id + ') and FOH "' + f.ch.name + '" (Ch ' + f.ch.id + ') both come from ' + keyLabel(key) + '. Same physical signal — names just differ between desks.',
      });
    }
  }

  const order = { error: 0, warn: 1, info: 2 };
  issues.sort((a, b) => order[a.sev] - order[b.sev]);

  return { link, monCh, fohCh, monByKey, fohByKey, bSend, forwarded, issues, nameMismatch };
}
