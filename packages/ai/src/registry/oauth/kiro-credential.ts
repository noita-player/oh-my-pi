import { decodeKiroCredential, encodeKiroCredential } from "@oh-my-pi/pi-catalog/wire/kiro-credential";
import * as AIError from "../../error";
import type { OAuthCredentials } from "./types";

/**
 * Encode a stored Kiro OAuth row at the auth boundary. The catalog codec stays
 * credential-store agnostic; this wrapper classifies irreparable persisted
 * routing state as a definitive OAuth failure.
 */
export function encodeKiroOAuthCredential(credentials: OAuthCredentials): string {
	const { access, apiEndpoint, kiroLoginId, orgId } = credentials;
	try {
		if (!apiEndpoint || !kiroLoginId) throw new Error("missing route or login id");
		const encoded = encodeKiroCredential({
			kind: "oauth",
			token: access,
			apiEndpoint,
			loginId: kiroLoginId,
			...(orgId ? { profileArn: orgId } : {}),
		});
		decodeKiroCredential(encoded, {});
		return encoded;
	} catch (cause) {
		throw new AIError.OAuthError("Kiro login has invalid routing state; run /login kiro again", {
			kind: "configuration",
			provider: "kiro",
			definitive: true,
			cause,
		});
	}
}
