import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, setOperatorToken, wsUrl } from "./api";

afterEach(() => {
  setOperatorToken("");
  vi.unstubAllGlobals();
});

describe("api client", () => {
  it("sends the operator token as a header and never in the URL path", async () => {
    setOperatorToken("tok-123");
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ role: "viewer" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await api.me();
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("/api/me");
    expect(new Headers(init.headers).get("X-Operator-Token")).toBe("tok-123");
  });

  it("passes the token to the WebSocket as a query parameter only when one is set", () => {
    expect(wsUrl()).not.toContain("token=");
    setOperatorToken("a b&c");
    expect(wsUrl()).toContain("token=a%20b%26c");
  });

  it("turns network failure into a clear unreachable error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("failed")));
    await expect(api.me()).rejects.toMatchObject({ status: 0, message: expect.stringContaining("unreachable") });
  });

  it("surfaces the server's reason for a 403", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: "operator role required" }), { status: 403 })));
    const err = await api.reopen(1).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 403, message: "operator role required" });
  });

  it("encodes timeline entry ids but keeps the colon readable", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({}), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await api.timelineEntry(4, "metric:2026-03-10T16:00:00+00:00");
    expect(String(fetchMock.mock.calls[0][0])).toBe("/api/incidents/4/timeline/metric:2026-03-10T16%3A00%3A00%2B00%3A00".replace(/%3A/g, ":"));
  });
});
