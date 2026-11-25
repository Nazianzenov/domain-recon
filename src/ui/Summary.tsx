import type { SummaryView } from '@/lib/summary';
import type { RootInfo } from './state';

function Row({ label, children }: { label: string; children: preact.ComponentChildren }) {
  return (
    <div class="sum-row">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

export function Summary({ root, view }: { root: RootInfo; view: SummaryView }) {
  const h = view.headline;
  const age = h.domainAgeDays;
  return (
    <section class="summary" aria-label="Investigation summary">
      <h2 class="sum-domain">
        {/* Isolated LTR: right-to-left IDN labels must not visually reorder the name. */}
        <bdi dir="ltr">{root.unicode}</bdi>
        {root.isIdn ? (
          <span class="puny">
            {' ('}
            <bdi dir="ltr">{root.domain}</bdi>
            {')'}
          </span>
        ) : null}
      </h2>
      {root.isIdn ? (
        <p class="warn-text">Internationalised domain: check for look-alike characters.</p>
      ) : null}
      <dl class="sum-grid">
        <Row label="Domain age">
          {age !== undefined ? (
            <>
              <strong class={age < 30 ? 'tone-bad' : age < 180 ? 'tone-warn' : ''}>{age.toLocaleString()} days</strong>
              {h.registrationFor && h.registrationFor !== root.domain ? (
                <span class="muted"> (of parent {h.registrationFor})</span>
              ) : null}
            </>
          ) : (
            <span class="muted">—</span>
          )}
        </Row>
        <Row label="Registrar">{h.registrar ?? <span class="muted">—</span>}</Row>
        <Row label="M365 tenant">
          {h.m365 ? (
            h.m365.tenant ? (
              `yes${h.m365.namespaceType ? ` (${h.m365.namespaceType})` : ''}`
            ) : h.m365.namespaceType === 'Consumer (MSA)' ? (
              'no (consumer Microsoft account domain)'
            ) : (
              'no'
            )
          ) : (
            <span class="muted">—</span>
          )}
        </Row>
        <Row label="Email providers">
          {h.emailProviders?.length ? h.emailProviders.join(', ') : <span class="muted">—</span>}
        </Row>
        <Row label="IPs investigated">{view.ipCount}</Row>
        <Row label="Worst reputation">
          {view.worst ? (
            <span class={`sev-text sev-${view.worst.severity}`}>
              {view.worst.severity} · {view.worst.label} ({view.worst.entity.value})
            </span>
          ) : (
            <span class="muted">no hits</span>
          )}
        </Row>
        <Row label="AI brand">
          {h.brand ? (
            h.brand.brand ? (
              `${h.brand.brand} (${Math.round(h.brand.confidence * 100)}%, impersonation ${h.brand.impersonation})`
            ) : (
              'no brand identified'
            )
          ) : (
            <span class="muted">—</span>
          )}
        </Row>
      </dl>
    </section>
  );
}
