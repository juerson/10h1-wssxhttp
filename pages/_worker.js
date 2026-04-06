// pages调用Worker的DO，仅支持ws，不支持xhttp
// 需要绑定耐用对象(Durable object)，还有确保worker端绑定自定义域能正常使用，再考虑pages调用

const URLS = [
  'https://www.bilibili.com',
  'https://www.nicovideo.jp',
  'https://tv.naver.com',
  'https://www.hotstar.com',
  'https://www.netflix.com',
  'https://www.dailymotion.com',
  'https://www.youtube.com',
  'https://www.hulu.com',
  'https://fmovies.llc',
  'https://hdtodayz.to',
  'https://radar.cloudflare.com',
];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!request.headers.get("Upgrade")?.toLowerCase().includes("websocket")) {
      if (url.pathname === "/") {
        const redirectUrl = URLS[Math.floor(Math.random() * URLS.length)];
        return Response.redirect(redirectUrl, 301);
      }
      return new Response(null, { status: 404 });
    }

    const id = env.WS_CHAN.idFromName(url.pathname);
    const stub = env.WS_CHAN.get(id);
    return stub.fetch(request);
  }
};