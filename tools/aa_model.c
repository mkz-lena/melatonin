#include <stdio.h>
#include <stdint.h>
#include <math.h>

/*
 * Arithmetic model of CVE-2026-86950 (CoreGraphics aa_* path rasterizer).
 *
 * Not an exploit and not a payload generator. It reproduces the two
 * conversions and the bbox update from the public analysis so the failure
 * mode can be inspected and regression-tested on any host.
 *
 * pre-26.7.1 behaviour, as compiled:
 *   aa_moveto  -> FCVTZS Wd, Dn     : saturates to INT32_MIN / INT32_MAX
 *   aa_lineto  -> FCVTZS Xd, Dn     : 64-bit result, then XTN keeps low 32 bits
 * the mismatch lets a huge coordinate wrap the delta used for the bbox test,
 * so the recorded bbox can be far narrower than the edges actually drawn.
 */

static int32_t fcvt32(double v) {
    if (isnan(v)) return 0;
    if (v >= 2147483647.0) return INT32_MAX;
    if (v <= -2147483648.0) return INT32_MIN;
    return (int32_t)v;                     /* truncating, like FCVTZS */
}

static int32_t fixed_moveto(double px) { return fcvt32(0.5 + 4096.0 * px); }

static int32_t fixed_lineto(double px) {
    double v = 0.5 + 4096.0 * px;
    int64_t wide = (int64_t)v;             /* FCVTZS Xd, Dn */
    return (int32_t)(uint32_t)(uint64_t)wide;   /* XTN Wd, Wn */
}

struct bbox { int32_t min_x, max_x, cur_x; };

static void moveto(struct bbox *b, double x) {
    b->cur_x = fixed_moveto(x);
    b->min_x = b->max_x = b->cur_x;
}

static void lineto(struct bbox *b, double x) {
    int32_t nx = fixed_lineto(x);
    int32_t dx = (int32_t)((uint32_t)nx - (uint32_t)b->cur_x);   /* wraps */

    if (dx < 1) {
        if (b->min_x > nx)       b->min_x = nx;
        if (b->max_x < b->cur_x) b->max_x = b->cur_x;
    } else {
        if (b->min_x > b->cur_x) b->min_x = b->cur_x;
        if (b->max_x < nx)       b->max_x = nx;
    }
    b->cur_x = nx;
}

/* coverage buffer sizing from aa_cache_render */
static long coverage_bytes(int32_t min_x, int32_t max_x) {
    int32_t width_px = (int32_t)((uint32_t)max_x - (uint32_t)min_x) / 4096;
    return 4L * ((long)width_px + 16);
}

/* worst pixel column an edge endpoint can touch, relative to bbox_min */
static long required_bytes(int32_t min_x, const double *xs, int n) {
    long worst = 0;

    for (int i = 0; i < n; i++) {
        int32_t fx = (i == 0) ? fixed_moveto(xs[i]) : fixed_lineto(xs[i]);
        int32_t col = (int32_t)((uint32_t)fx - (uint32_t)min_x) / 4096;
        if (col + 1 > worst) worst = col + 1;
    }
    return 4L * (worst > 0 ? worst : 0);
}

struct probe { double xs[8]; int n; long alloc, need; int32_t lo, hi; };

static int evaluate(const double *xs, int n, struct probe *out) {
    struct bbox b;
    moveto(&b, xs[0]);
    for (int i = 1; i < n; i++) lineto(&b, xs[i]);

    out->n = n;
    for (int i = 0; i < n; i++) out->xs[i] = xs[i];
    out->lo = b.min_x;
    out->hi = b.max_x;
    out->alloc = coverage_bytes(b.min_x, b.max_x);
    out->need  = required_bytes(b.min_x, xs, n);
    return out->need > out->alloc;
}

int main(void) {
    static const double mags[] = {
        5.2e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e12, 1e15
    };
    const int nm = (int)(sizeof mags / sizeof mags[0]);

    struct probe p, hit;
    int found = 0;

    printf("%-11s %-11s %-11s %-11s %-11s %s\n",
           "m0", "m1", "m2", "alloc", "need", "result");

    for (int a = 0; a < nm && !found; a++) {
        for (int s0 = -1; s0 <= 1 && !found; s0 += 2) {
            for (int s1 = -1; s1 <= 1 && !found; s1 += 2) {
                double xs[3] = { s0 * mags[a], s1 * mags[a], s0 * mags[a] };
                int oob = evaluate(xs, 3, &p);

                printf("%-11.3g %-11.3g %-11.3g %-11ld %-11ld %s\n",
                       xs[0], xs[1], xs[2], p.alloc, p.need,
                       oob ? "underallocated" : "ok");

                if (oob && p.alloc > 0) { hit = p; found = 1; }
            }
        }
    }

    if (!found) {
        printf("model: no divergent case found\n");
        return 1;
    }

    printf("model: bbox [%d, %d], allocation %ld bytes, edges need %ld\n",
           hit.lo, hit.hi, hit.alloc, hit.need);
    return 0;
}

