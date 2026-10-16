import type { OpenClawConfig } from "../config/types.openclaw.js";
import { resolveCreatorSandbox } from "../gateway/operator-role-policy.js";
import { prepareUserChannelIdentityAuthority } from "../state/user-channel-identity-operations.js";
import { UserProfileNotFoundError } from "../state/user-profiles-schema.js";
import { resolveCronAuthenticatedCallerOrigin } from "./tools-allow-provenance.js";
import type { CronStoredJob } from "./types.js";

/** Resolve shipped native sender stamps without changing their historical provenance. */
export async function resolveCronCreatorSandbox(cfg: OpenClawConfig, job: CronStoredJob) {
  let creator = job.createdActor;
  if (cfg.gateway?.roles && creator?.type === "human" && creator.source === "channel") {
    const origin = resolveCronAuthenticatedCallerOrigin(job);
    const accountId = job.owner?.accountId;
    const linked =
      origin?.kind === "external" && accountId && creator.id
        ? await prepareUserChannelIdentityAuthority({
            channelId: origin.channel,
            accountId,
            senderId: creator.id,
          })
        : undefined;
    if (!linked || !linked.isCurrent()) {
      throw new UserProfileNotFoundError(creator.id ?? "");
    }
    creator = { type: "human", source: "profile", id: linked.linked.profileId };
  }
  return resolveCreatorSandbox(cfg, { actor: creator });
}
