package atlassian

import (
	"context"
	"errors"
	"math/rand"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"testing"
)

func TestConfluenceHistoryNumbersStayWithinBodyBudget(t *testing.T) {
	for _, cloud := range []bool{false, true} {
		for _, order := range []string{"ascending", "descending", "shuffled"} {
			t.Run(strconv.FormatBool(cloud)+"/"+order, func(t *testing.T) {
				const total = maxVersionsPerPage + 1501
				const batch = 700
				calls := 0
				c := NewClient("https://fixture.invalid", Auth{}, 0)
				c.http = &http.Client{Transport: fixtureTransport(func(r *http.Request) (int, any) {
					start, _ := strconv.Atoi(r.URL.Query().Get("start"))
					if cloud {
						start, _ = strconv.Atoi(r.URL.Query().Get("cursor"))
					}
					calls++
					end := min(start+batch, total)
					results := make([]any, 0, end-start)
					for i := start; i < end; i++ {
						n := i + 1
						switch order {
						case "descending":
							n = total - i
						case "shuffled":
							n = (i*997)%total + 1
						}
						results = append(results, map[string]any{"number": n})
					}
					page := map[string]any{"results": results}
					if end < total {
						page["_links"] = map[string]any{"next": "/next?cursor=" + strconv.Itoa(end)}
					}
					return 200, page
				})}
				var got []int
				var capped bool
				var err error
				if cloud {
					got, capped, err = confCloudPageVersions(context.Background(), c, "1")
				} else {
					got, capped, err = confServerPageVersions(context.Background(), c, "1")
				}
				want := make([]int, maxVersionsPerPage)
				for i := range want {
					want[i] = total - maxVersionsPerPage + i + 1
				}
				if err != nil || !capped || !reflect.DeepEqual(got, want) || calls != (total+batch-1)/batch {
					t.Fatalf("history retains an unbounded list or loses recent versions: numbers=%d requests=%d err=%v", len(got), calls, err)
				}
			})
		}
	}
}

func TestVersionWindowMatchesUnboundedOracleWithoutGrowing(t *testing.T) {
	const limit = 64
	for seed := int64(0); seed < 20; seed++ {
		rng := rand.New(rand.NewSource(seed))
		window := newBoundedVersions(limit)
		seen := map[int]bool{}
		for i := 0; i < 2000; i++ {
			n := rng.Intn(500) - 5
			if n > 0 {
				seen[n] = true
			}
			window.add(n)
			if len(window.nums) > limit || len(window.seen) > limit {
				t.Fatal("history bookkeeping exceeded its memory bound")
			}
		}
		want := make([]int, 0, len(seen))
		for n := range seen {
			want = append(want, n)
		}
		sort.Ints(want)
		capped := len(want) > limit
		if capped {
			want = want[len(want)-limit:]
		}
		got, gotCapped := window.window()
		if !reflect.DeepEqual(got, want) || gotCapped != capped {
			t.Fatalf("bounded selection disagrees with all-number oracle: seed=%d", seed)
		}
		got[0] = -1
		again, _ := window.window()
		if !reflect.DeepEqual(again, want) {
			t.Fatal("caller can corrupt the retained version window")
		}
	}
	for _, limit := range []int{0, 1, 3} {
		window := newBoundedVersions(limit)
		for i := 0; i < 10000; i++ {
			window.add(i%3 + 1)
		}
		got, capped := window.window()
		if len(got) != min(limit, 3) || capped != (limit < 3) {
			t.Fatal("duplicates consume budget or an empty window panics")
		}
	}
}

func TestConfluenceCappedHistoryKeepsPrefixOnLaterFailure(t *testing.T) {
	for _, cloud := range []bool{false, true} {
		for _, mode := range []string{"http", "invalid-json", "cancel", "empty-more", "fallback-http"} {
			if cloud && mode == "fallback-http" {
				continue
			}
			t.Run(strconv.FormatBool(cloud)+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				c := NewClient("https://fixture.invalid", Auth{}, 0)
				c.http = &http.Client{Transport: fixtureTransport(func(r *http.Request) (int, any) {
					calls++
					if mode == "fallback-http" && calls == 1 {
						return 404, nil
					}
					if r.URL.Query().Get("cursor") != "" || r.URL.Query().Get("start") != "0" && !cloud {
						switch mode {
						case "cancel":
							cancel()
							return 200, map[string]any{"results": []any{}}
						case "invalid-json":
							return 200, map[string]any{"error": "owned-error"}
						case "empty-more":
							return 200, map[string]any{"results": []any{}, "_links": map[string]any{"next": "/next?cursor=a"}}
						default:
							return 500, nil
						}
					}
					results := make([]any, maxVersionsPerPage+1)
					for i := range results {
						results[i] = map[string]any{"number": i + 1}
					}
					return 200, map[string]any{"results": results, "_links": map[string]any{"next": "/next?cursor=a"}}
				})}
				var got []int
				var capped bool
				var err error
				if cloud {
					got, capped, err = confCloudPageVersions(ctx, c, "1")
				} else {
					got, capped, err = confServerPageVersions(ctx, c, "1")
				}
				wantCalls := 2
				if mode == "fallback-http" {
					wantCalls++
				}
				if err == nil || !capped || len(got) != maxVersionsPerPage || got[0] != 2 || got[len(got)-1] != maxVersionsPerPage+1 || calls != wantCalls {
					t.Fatalf("later failure lost bounded prefix or cap: numbers=%d capped=%v calls=%d err=%v", len(got), capped, calls, err)
				}
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal("history lost cancellation identity")
				}
			})
		}
	}
}
