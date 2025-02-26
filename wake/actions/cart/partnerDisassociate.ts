import { HttpError } from "../../../utils/http.ts";
import { AppContext } from "../../mod.ts";
import { getCartCookie, setCartCookie } from "../../utils/cart.ts";
import { CheckoutPartnerDisassociate } from "../../utils/graphql/queries.ts";
import {
  CheckoutFragment,
  CheckoutPartnerDisassociateMutation,
  CheckoutPartnerDisassociateMutationVariables,
} from "../../utils/graphql/storefront.graphql.gen.ts";
import { parseHeaders } from "../../utils/parseHeaders.ts";
import { deletePartnerCookie } from "../../utils/partner.ts";

const action = async (
  _props: unknown,
  req: Request,
  ctx: AppContext,
): Promise<Partial<CheckoutFragment>> => {
  const { storefront } = ctx;
  const cartId = getCartCookie(req.headers);
  const headers = parseHeaders(req.headers);

  if (!cartId) {
    throw new HttpError(400, "Missing cart cookie");
  }

  const data = await storefront.query<
    CheckoutPartnerDisassociateMutation,
    CheckoutPartnerDisassociateMutationVariables
  >({
    variables: { checkoutId: cartId },
    ...CheckoutPartnerDisassociate,
  }, { headers });

  const checkoutId = data.checkout?.checkoutId;

  if (cartId !== checkoutId) {
    setCartCookie(ctx.response.headers, checkoutId);
  }

  deletePartnerCookie(ctx.response.headers);

  return data.checkout ?? {};
};

export default action;
