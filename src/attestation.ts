import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import * as core from '@actions/core'
import { bundleFromJSON } from '@sigstore/bundle'
import type { SerializedBundle } from '@sigstore/bundle'
import { TrustedRoot } from '@sigstore/protobuf-specs'
import { getTrustedRoot } from '@sigstore/tuf'
import { toSignedEntity, toTrustMaterial, Verifier } from '@sigstore/verify'
import bundledTrustedRoot from './trusted-root/trusted_root.json'
import bundledTufRoot from './trusted-root/tuf-root.json'
import { fetchWithRetry, sha256, USER_AGENT } from './util'

// GitHub creates a release attestation for every asset of an immutable release.
// The attestation is signed by GitHub's own Sigstore instance, whose trust root is distributed via this TUF repository.
const GITHUB_TUF_MIRROR = 'https://tuf-repo.github.com'
const GITHUB_API_URL = 'https://api.github.com'
const RELEASE_ATTESTATION_SIGNER = 'https://dotcom.releases.github.com'
const IN_TOTO_STATEMENT_TYPE = 'https://in-toto.io/Statement/v1'
const IN_TOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json'
const RELEASE_PREDICATE_TYPE = 'https://in-toto.io/attestation/release/v0.2'

// Compare IDs in addition to the name so that a renamed or re-registered repository can't pass as pixi.
export const PIXI_REPOSITORY = {
  name: 'prefix-dev/pixi',
  repositoryId: '633817517',
  ownerId: '111356225'
} as const

export const FIRST_IMMUTABLE_PIXI_RELEASE = 'v0.72.0'

export type TrustedRootSource = 'tuf' | 'bundled'

type Statement = {
  _type?: string
  predicateType?: string
  subject?: { name?: string; digest?: Record<string, string> }[]
  predicate?: { repository?: string; repositoryId?: string; ownerId?: string; tag?: string }
}

type AttestationsResponse = {
  attestations?: { bundle?: SerializedBundle | null }[]
}

const optOutHint = 'To skip this check, set `verify-attestation: false`.'

/**
 * Loads the trusted root for verifying release attestations.
 * It doesn't depend on the pixi binary, so callers can start loading it while the binary downloads.
 */
export const loadTrustedRoot = async (source: TrustedRootSource): Promise<TrustedRoot> => {
  if (source === 'bundled') {
    core.info('Using the trusted root bundled with setup-pixi.')
    return TrustedRoot.fromJSON(bundledTrustedRoot)
  }
  core.info(`Fetching the trusted root from ${GITHUB_TUF_MIRROR}.`)
  const tufDir = await fs.mkdtemp(path.join(process.env.RUNNER_TEMP ?? os.tmpdir(), 'setup-pixi-tuf-'))
  try {
    const rootPath = path.join(tufDir, 'root.json')
    await fs.writeFile(rootPath, JSON.stringify(bundledTufRoot))
    return await getTrustedRoot({
      mirrorURL: GITHUB_TUF_MIRROR,
      rootPath,
      cachePath: path.join(tufDir, 'cache'),
      forceInit: true
    })
  } catch (error) {
    throw new Error(
      `Could not fetch the trusted root from ${GITHUB_TUF_MIRROR}: ${(error as Error).message}\n` +
        'If this host is not reachable from your runner, set `attestation-trusted-root: bundled`.',
      { cause: error }
    )
  } finally {
    await fs.rm(tufDir, { recursive: true, force: true })
  }
}

const fetchAttestations = async (digest: string, githubToken: string | undefined) => {
  const url = `${GITHUB_API_URL}/repos/${PIXI_REPOSITORY.name}/attestations/sha256:${digest}?predicate_type=release`
  core.debug(`Fetching attestations from ${url}`)
  const response = await fetchWithRetry(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': USER_AGENT,
      ...(githubToken ? { Authorization: `Bearer ${githubToken}` } : {})
    }
  })
  if (response.status === 404) {
    throw new Error(
      `No release attestation found in ${PIXI_REPOSITORY.name} for the downloaded pixi binary (sha256:${digest}). ` +
        `Only immutable releases have attestations, which pixi publishes since ${FIRST_IMMUTABLE_PIXI_RELEASE}. ` +
        optOutHint
    )
  }
  if (response.status === 401) {
    throw new Error('GitHub rejected `github-token` while fetching the release attestation (HTTP 401).')
  }
  const rateLimited =
    response.status === 429 || (response.status === 403 && response.headers.get('x-ratelimit-remaining') === '0')
  if (rateLimited) {
    throw new Error(
      'Hit the GitHub API rate limit while fetching the release attestation. ' +
        (githubToken
          ? 'Wait for the rate limit to reset. '
          : 'Unauthenticated requests are limited to 60 per hour; set `github-token` to a github.com token. ') +
        optOutHint
    )
  }
  if (!response.ok) {
    throw new Error(
      `Fetching the release attestation failed with HTTP ${response.status}: ${await response.text()}\n${optOutHint}`
    )
  }
  const body = (await response.json()) as AttestationsResponse
  return (body.attestations ?? []).map((a) => a.bundle).filter((b): b is SerializedBundle => !!b)
}

/** Returns the release tag the binary was attested for, or throws if the bundle doesn't match. */
const verifyBundle = (
  serializedBundle: SerializedBundle,
  verifier: Verifier,
  digest: string,
  expectedTag: string | undefined
): string => {
  const bundle = bundleFromJSON(serializedBundle)
  // Checks the certificate chain, the RFC 3161 timestamp and the signature over the DSSE envelope.
  verifier.verify(toSignedEntity(bundle), { subjectAlternativeName: RELEASE_ATTESTATION_SIGNER })

  if (bundle.content.$case !== 'dsseEnvelope') {
    throw new Error('attestation is not a DSSE envelope')
  }
  const envelope = bundle.content.dsseEnvelope
  if (envelope.payloadType !== IN_TOTO_PAYLOAD_TYPE) {
    throw new Error(`unexpected payload type ${envelope.payloadType}`)
  }
  const statement = JSON.parse(envelope.payload.toString('utf8')) as Statement
  if (statement._type !== IN_TOTO_STATEMENT_TYPE) {
    throw new Error(`unexpected statement type ${statement._type}`)
  }
  if (statement.predicateType !== RELEASE_PREDICATE_TYPE) {
    throw new Error(`unexpected predicate type ${statement.predicateType}`)
  }
  const predicate = statement.predicate ?? {}
  if (
    predicate.repositoryId !== PIXI_REPOSITORY.repositoryId ||
    predicate.ownerId !== PIXI_REPOSITORY.ownerId ||
    predicate.repository?.toLowerCase() !== PIXI_REPOSITORY.name
  ) {
    throw new Error(
      `attestation is for repository ${predicate.repository} (id ${predicate.repositoryId}, owner id ${predicate.ownerId})`
    )
  }
  const subject = statement.subject?.find((s) => s.digest?.sha256 === digest)
  if (!subject) {
    throw new Error(`attestation does not cover sha256:${digest}`)
  }
  if (!predicate.tag) {
    throw new Error('attestation has no release tag')
  }
  if (expectedTag !== undefined && predicate.tag !== expectedTag) {
    throw new Error(`attestation is for release ${predicate.tag}, expected ${expectedTag}`)
  }
  core.debug(`Attestation subject: ${subject.name}`)
  return predicate.tag
}

/**
 * Verifies that the pixi binary at `binaryPath` is an asset of an immutable prefix-dev/pixi release,
 * using the release attestation GitHub creates for it.
 * If `expectedTag` is set, the attestation must be for exactly that release.
 */
export const verifyPixiAttestation = async ({
  binaryPath,
  expectedTag,
  githubToken,
  trustedRoot,
  trustedRootSource
}: {
  binaryPath: string
  expectedTag: string | undefined
  githubToken: string | undefined
  trustedRoot: Promise<TrustedRoot>
  trustedRootSource: TrustedRootSource
}) => {
  const digest = sha256(await fs.readFile(binaryPath))
  core.info(`Verifying release attestation for pixi binary sha256:${digest}`)

  const bundles = await fetchAttestations(digest, githubToken)
  if (bundles.length === 0) {
    throw new Error(`GitHub returned no release attestation for sha256:${digest}. ${optOutHint}`)
  }

  // GitHub's Sigstore instance doesn't use transparency logs; it proves signing time with an RFC 3161 timestamp.
  const verifier = new Verifier(toTrustMaterial(await trustedRoot), {
    tlogThreshold: 0,
    ctlogThreshold: 0,
    timestampThreshold: 1
  })

  const failures: string[] = []
  for (const bundle of bundles) {
    try {
      const tag = verifyBundle(bundle, verifier, digest, expectedTag)
      core.info(`Verified: the pixi binary is an asset of the immutable ${PIXI_REPOSITORY.name} release ${tag}.`)
      return tag
    } catch (error) {
      failures.push((error as Error).message)
    }
  }
  const hint =
    trustedRootSource === 'bundled'
      ? '\nThe bundled trusted root may be too old for this release; upgrade setup-pixi or use `attestation-trusted-root: tuf`.'
      : ''
  throw new Error(
    `Release attestation verification failed for sha256:${digest}:\n${failures.map((f) => `- ${f}`).join('\n')}${hint}`
  )
}
