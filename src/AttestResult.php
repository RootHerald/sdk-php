<?php

declare(strict_types=1);

namespace Rootherald;

/**
 * The result of {@see BackgroundCheck::attest}: the device verdict plus, when
 * requested, the signed EAT (JWT). The token is itself verifiable offline with
 * {@see AttestationTokenVerifier}.
 */
final class AttestResult
{
    /**
     * @param array<string, mixed> $verdictData the full decoded verdict object
     */
    public function __construct(
        public readonly Verdict $verdict,
        public readonly array $verdictData,
        public readonly ?string $token = null,
    ) {
    }

    /**
     * The raw `device` sub-object of the verdict, passed through verbatim.
     *
     * In addition to the per-device appraisal, when a quote-bound event log was
     * supplied the server populates ADDITIVE, advisory-only cohort fields here
     * (camelCase keys; absent otherwise) — never a trust gate. See the cohort*()
     * / novelProfile() accessors below.
     *
     * @return array<string, mixed>
     */
    public function device(): array
    {
        $device = $this->verdictData['device'] ?? null;

        return is_array($device) ? $device : [];
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
