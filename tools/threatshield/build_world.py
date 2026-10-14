#!/usr/bin/env python3
"""Builds the Threat Shield world map assets from Natural Earth (public domain).

Development-time only; the outputs are committed:
  files/usr/local/www/threatshield/assets/ts-world.js
      window.TSWorld: Equal Earth projected country outlines (110m), a land
      dot grid for the "hacker" style and the projection constants used by
      threatshield_map.js
  files/usr/local/pkg/threatshield/threatshield_geo_countries.inc
      threatshield_geo_countries(): ISO code => [name, lat, lon, spread]
      (label points and size of the 50m countries) for placing map dots

Usage:
  python tools/threatshield/build_world.py ne_110m_admin_0_countries.geojson \
      ne_50m_admin_0_countries.geojson

Natural Earth: https://www.naturalearthdata.com/ (public domain).
"""
import json
import math
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'security', 'FreeSense-pkg-ThreatShield', 'files', 'usr', 'local')
WIDTH = 1000.0          # map width in units; paths are stored at 10x that
SCALE = 10
DOT_STEP = 2.0          # degrees between land dots

A1, A2, A3, A4 = 1.340264, -0.081106, 0.000893, 0.003796
M = math.sqrt(3) / 2


def equal_earth(lon, lat):
    lam, phi = math.radians(lon), math.radians(lat)
    theta = math.asin(M * math.sin(phi))
    t2 = theta * theta
    t6 = t2 * t2 * t2
    x = 2 * math.sqrt(3) * lam * math.cos(theta) / (3 * (9 * A4 * t6 * t2 + 7 * A3 * t6 + 3 * A2 * t2 + A1))
    y = theta * (A4 * t6 * t2 + A3 * t6 + A2 * t2 + A1)
    return x, y


def iso(props):
    code = props.get('ISO_A2')
    if code in (None, '-99'):
        code = props.get('ISO_A2_EH')
    return None if code in (None, '-99') else code.upper()


def polygons(geom):
    if geom['type'] == 'Polygon':
        return [geom['coordinates']]
    if geom['type'] == 'MultiPolygon':
        return geom['coordinates']
    return []


def ring_area(ring):
    a = 0.0
    for (x1, y1), (x2, y2) in zip(ring, ring[1:] + ring[:1]):
        a += x1 * y2 - x2 * y1
    return abs(a) / 2


def point_in_ring(x, y, ring):
    inside = False
    n = len(ring)
    j = n - 1
    for i in range(n):
        xi, yi = ring[i][0], ring[i][1]
        xj, yj = ring[j][0], ring[j][1]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside


def main(path110, path50):
    world = json.load(open(path110, encoding='utf-8'))
    feats = [f for f in world['features'] if iso(f['properties']) and iso(f['properties']) != 'AQ']

    # projection bounds over every country except Antarctica
    xs, ys = [], []
    for f in feats:
        for poly in polygons(f['geometry']):
            for lon, lat in poly[0]:
                x, y = equal_earth(lon, lat)
                xs.append(x)
                ys.append(y)
    xmin, xmax = equal_earth(-180, 0)[0], equal_earth(180, 0)[0]
    ymin, ymax = min(ys), max(ys)
    k = WIDTH / (xmax - xmin)
    pad = 6.0
    height = round((ymax - ymin) * k + 2 * pad, 1)
    tx = -xmin * k
    ty = ymax * k + pad

    def project(lon, lat):
        x, y = equal_earth(lon, lat)
        return tx + k * x, ty - k * y

    paths = {}
    names = {}
    for f in feats:
        code = iso(f['properties'])
        names[code] = f['properties']['NAME']
        out = []
        for poly in polygons(f['geometry']):
            for ring in poly:
                pts = [project(lon, lat) for lon, lat in ring]
                ipts = [(round(x * SCALE), round(y * SCALE)) for x, y in pts]
                cmd = []
                px, py = ipts[0]
                cmd.append('M%d %d' % (px, py))
                for x, y in ipts[1:]:
                    dx, dy = x - px, y - py
                    if dx == 0 and dy == 0:
                        continue
                    cmd.append('l%d %d' % (dx, dy))
                    px, py = x, y
                if len(cmd) > 2:
                    out.append(''.join(cmd) + 'z')
        if out:
            paths[code] = paths.get(code, '') + ''.join(out)

    # land dots for the dot-matrix look: grid cells whose centre is on land
    rings = []
    for f in feats:
        for poly in polygons(f['geometry']):
            ring = poly[0]
            lons = [p[0] for p in ring]
            lats = [p[1] for p in ring]
            rings.append((min(lons), max(lons), min(lats), max(lats), ring))
    dots = []
    lat = 84.0 - DOT_STEP / 2
    while lat > -60:
        lon = -180 + DOT_STEP / 2
        while lon < 180:
            for x0, x1, y0, y1, ring in rings:
                if x0 <= lon <= x1 and y0 <= lat <= y1 and point_in_ring(lon, lat, ring):
                    x, y = project(lon, lat)
                    dots.append(round(x * SCALE))
                    dots.append(round(y * SCALE))
                    break
            lon += DOT_STEP
        lat -= DOT_STEP

    world_js = {
        'w': WIDTH, 'h': height, 's': SCALE,
        'proj': {'k': round(k, 6), 'tx': round(tx, 4), 'ty': round(ty, 4)},
        'c': paths, 'n': names, 'dots': dots,
        'src': 'Natural Earth 1:110m, public domain',
    }
    js_path = os.path.join(ROOT, 'www', 'threatshield', 'assets', 'ts-world.js')
    os.makedirs(os.path.dirname(js_path), exist_ok=True)
    with open(js_path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('/* Threat Shield world map: Natural Earth 1:110m (public domain), Equal Earth projection.\n')
        fh.write(' * Generated by tools/threatshield/build_world.py; do not edit. */\n')
        fh.write('window.TSWorld = ' + json.dumps(world_js, separators=(',', ':'), ensure_ascii=False) + ';\n')

    # label points and size of the 50m countries (dots placement)
    fifty = json.load(open(path50, encoding='utf-8'))
    rows = {}
    for f in fifty['features']:
        p = f['properties']
        code = iso(p)
        if not code or code in rows:
            continue
        area = 0.0
        for poly in polygons(f['geometry']):
            area += ring_area(poly[0]) * math.cos(math.radians(p.get('LABEL_Y') or 0))
        spread = max(0.25, min(7.0, math.sqrt(area) * 0.22))
        rows[code] = (p['NAME'], round(p['LABEL_Y'], 3), round(p['LABEL_X'], 3), round(spread, 2))
    inc_path = os.path.join(ROOT, 'pkg', 'threatshield', 'threatshield_geo_countries.inc')
    with open(inc_path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('<?php\n/*\n * threatshield_geo_countries.inc\n')
        fh.write(' * FreeSense Threat Shield - country names, label points and size\n')
        fh.write(' * Generated by tools/threatshield/build_world.py from Natural Earth 1:50m\n')
        fh.write(' * (public domain); do not edit.\n *\n')
        fh.write(' * Copyright (c) 2025-2026 The FreeSense Project.\n')
        fh.write(' * Licensed under the Apache License, Version 2.0.\n */\n\n')
        fh.write('/* ISO 3166-1 alpha-2 => [name, latitude, longitude, dot spread in degrees] */\n')
        fh.write('function threatshield_geo_countries(): array {\n\treturn [\n')
        for code in sorted(rows):
            name, lat, lon, spread = rows[code]
            fh.write("\t\t'%s' => [%s, %s, %s, %s],\n" % (code, json.dumps(name, ensure_ascii=False).replace('$', '\\$'), lat, lon, spread))
        fh.write('\t];\n}\n')

    print('countries: %d paths, %d label points; %d land dots; map %dx%s; js %d KB' % (
        len(paths), len(rows), len(dots) // 2, WIDTH, height, os.path.getsize(js_path) // 1024))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
