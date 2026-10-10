<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * The result of {@see Client::verify}: the device verdict and the full
 * decoded verdict object.
 */
final class AttestResult
{
    /**
     * @param array<string, mixed> $verdictData        the full decoded verdict object
     * @param list<string>         $assuranceClaimsMet assurance claim URNs the appraisal satisfied
     *        (top-level `assuranceClaimsMet`), mirroring `@rootherald/node`
     * @param bool                 $enrollmentRequired the attest-first / enroll-on-miss signal
     *        (top-level `enrollmentRequired`): the device must (re-)enroll before it can pass
     */
    public function __construct(
        public readonly Verdict $verdict,
        public readonly array $verdictData,
        public readonly array $assuranceClaimsMet = [],
        public readonly bool $enrollmentRequired = false,
    ) {
    }

    /**
     * The raw `device` sub-object of the verdict, passed through verbatim:
     * ueid, disclosureClass, earStatus, verdict, attestationType, attestedAt,
     * quoteVerified, secureBootVerified, eventLogVerified, postureEvaluated,
     * platform, tpmKind, hardwareGenuine, sybilResistance, returningDevice,
     * bootChanged, bootChangedStages, trustworthinessVector, and whatever
     * else the server sends. Fields gated by disclosure class are absent
     * below it.
     *
     * When a quote-bound event log was supplied the server also populates
     * ADDITIVE, advisory-only cohort fields here (camelCase keys; absent
     * otherwise) — never a trust gate. See the cohort*() / novelProfile()
     * accessors below.
     *
     * @return array<string, mixed>
     */
    public function device(): array
    {
        $device = $this->verdictData['device'] ?? null;

        return is_array($device) ? $device : [];
    }

    /** This tenant's alias for the device (`verdict.device.ueid`), or null below pseudonymous. */
    public function deviceId(): ?string
    {
        $v = $this->device()['ueid'] ?? null;

        return is_string($v) && $v !== '' ? $v : null;
    }

    /**
     * The binding the challenge named, echoed by the server after it was
     * enforced: `['key' => keyId]`, `['devices' => [alias, ...]]`, or both.
     * Null when the challenge named nothing. {@see Client::verify} compares
     * it with what the caller asked for.
     *
     * @return array{key?: string, devices?: list<string>}|null
     */
    public function expected(): ?array
    {
        $v = $this->verdictData['expected'] ?? null;
        if (!is_array($v)) {
            return null;
        }
        $out = [];
        if (is_string($v['key'] ?? null)) {
            $out['key'] = $v['key'];
        }
        if (is_array($v['devices'] ?? null)) {
            $out['devices'] = array_values(array_filter($v['devices'], 'is_string'));
        }

        return $out;
    }

    /** Opaque cohort key, or null if the server did not return one. */
    public function cohortKey(): ?string
    {
        $v = $this->device()['cohortKey'] ?? null;

        return is_string($v) ? $v : null;
    }

    /** Cohort comparison scope ("global" | "tenant-fleet"), or null. */
    public function cohortScope(): ?string
    {
        $v = $this->device()['cohortScope'] ?? null;

        return is_string($v) ? $v : null;
    }

    /** Fraction of the cohort sharing this profile, or null if unknown/absent. */
    public function cohortPrevalence(): ?float
    {
        $v = $this->device()['cohortPrevalence'] ?? null;

        return is_int($v) || is_float($v) ? (float) $v : null;
    }

    /**
     * Per-PCR prevalence map (PCR index => fraction); empty if absent.
     *
     * @return array<string, float>
     */
    public function cohortPrevalencePerPcr(): array
    {
        $v = $this->device()['cohortPrevalencePerPcr'] ?? null;
        if (!is_array($v)) {
            return [];
        }
        $out = [];
        foreach ($v as $pcr => $frac) {
            if (is_int($frac) || is_float($frac)) {
                $out[(string) $pcr] = (float) $frac;
            }
        }

        return $out;
    }

    /** Number of devices in the cohort sample, or null if unknown/absent. */
    public function cohortSampleSize(): ?int
    {
        $v = $this->device()['cohortSampleSize'] ?? null;

        return is_int($v) ? $v : null;
    }

    /** Whether this is a previously-unseen profile, or null if not evaluated. */
    public function novelProfile(): ?bool
    {
        $v = $this->device()['novelProfile'] ?? null;

        return is_bool($v) ? $v : null;
    }
}
