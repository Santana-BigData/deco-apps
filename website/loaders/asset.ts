import { forbidden } from "@deco/deco";
import { fetchSafe, STALE } from "../../utils/fetch.ts";

const ASSET_REDIRECT_ENABLE: boolean = Deno?.env.has("ASSET_REDIRECT_ENABLE");

interface Props {
  /**
   * @description Asset src like: https://fonts.gstatic.com/...
   */
  src: string;
}

const loader = async (props: Props, request: Request): Promise<Response> => {
  const url = new URL(props.src);

  // Whitelist allowed protocols
  const allowedProtocols = ["https:", "http:"];
  if (!allowedProtocols.includes(url.protocol)) {
    forbidden({
      message: "Only HTTP and HTTPS protocols are allowed",
    });
  }

  if (ASSET_REDIRECT_ENABLE) {
    return new Response("Asset Redirect is Enabled!", {
      status: 302,
      headers: { Location: url.href },
    });
  }

  const original = await fetchSafe(url.href, STALE);
  const response = new Response(original.body, original);

  // Check if the request's Accept header includes "text/html"
  const acceptHeader = request.headers.get("accept");
  if (acceptHeader && acceptHeader.includes("text/html")) {
    forbidden({
      message: "Forbidden: text/html not accepted",
    });
  }

  const contentType = response.headers.get("Content-Type");
  if (contentType && contentType.includes("text/html")) {
    forbidden({
      message: "Forbidden: text/html not accepted as a response",
    });
  }

  // Set strict Content-Security-Policy
  response.headers.set(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'",
  );

  // Set cache control headers
  response.headers.set(
    "Cache-Control",
    "public, s-maxage=15552000, max-age=15552000, immutable",
  );

  return response;
};

export default loader;
