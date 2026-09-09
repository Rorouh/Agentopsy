/**
 * La ficha de una CITA, abierta por el backend.
 *
 * Es lo que un tercero necesita para rehacer el camino: evidencia, ejecucion,
 * herramienta, artefacto, localizador y el extracto que hay AHI, con su estado
 * de integridad. Vive aqui, y no dentro de una pantalla, porque la abren dos: la
 * de Hallazgos, desde el hallazgo, y la del Informe, desde la conclusion que se
 * apoya en el (RA07). Dos copias derivarian, y la que se quedase atras seria la
 * que enseña un extracto sin decir que su fuente ya no verifica.
 *
 * La distincion que no puede difuminarse: `estado` es VALIDACION TECNICA (los
 * bytes son los que se registraron). Que la fuente sostenga la interpretacion
 * del hallazgo es REVISION HUMANA, y esta ficha no la afirma.
 */
import type { ResolvedSource } from "../api/types";
import { useLang } from "../i18n";
import { useFormat } from "../utils/format";

export function SourceCard({ source: s }: { source: ResolvedSource }) {
  const { t } = useLang();
  const { na } = useFormat();
  const ok = s.estado === "verificada";
  const loc = s.localizador;
  const localizador = !loc
    ? na
    : loc.tipo === "registro"
      ? t("source.locatorRecord", { value: loc.valor ?? "" })
      : loc.tipo === "bytes"
        ? t("source.locatorBytes", { from: loc.desde ?? 0, to: loc.hasta ?? 0 })
        : t("source.locatorLines", { from: loc.desde ?? 0, to: loc.hasta ?? 0 });

  const kv: Array<[string, string]> = [
    [t("finding.evidence"), s.evidence_id ?? na],
    [t("finding.run"), s.run_id ?? na],
    [t("finding.tool"), s.tool_id ?? na],
    [t("source.artifact"), s.relpath ?? s.artefacto ?? na],
    [t("source.locator"), localizador],
    [t("finding.artifactHash"), s.sha256 ?? s.sha256_registrado ?? na],
  ];

  return (
    <div className={`fuente-card${ok ? "" : " is-broken"}`} data-testid="fuente">
      <div className="fuente-head">
        <span className={`fuente-badge fuente-badge--${s.estado}`}>
          {t(`source.state.${s.estado}` as never)}
        </span>
        {s.anclaje === "sin_ancla" && (
          <span className="fuente-badge fuente-badge--aviso">{t("source.noAnchor")}</span>
        )}
        {s.resultado_parcial && (
          <span className="fuente-badge fuente-badge--aviso">
            {t("source.partial", { exit: s.exit_code ?? na })}
          </span>
        )}
      </div>

      <div className="report-kv">
        {kv.map(([k, v]) => (
          <div className="report-kv-row" key={k}>
            <span className="report-kv-k">{k}</span>
            <span className="report-kv-v">{v}</span>
          </div>
        ))}
      </div>

      {ok ? (
        s.extracto ? (
          // El extracto se pinta como TEXTO (nunca HTML): son bytes derivados de
          // la evidencia, que es dato hostil (SECURITY INVARIANT 8).
          <pre className="fuente-extracto" data-testid="fuente-extracto">
            {s.extracto}
          </pre>
        ) : (
          <p className="report-p report-p--muted">{t("source.noExcerpt")}</p>
        )
      ) : (
        // Una fuente rota NO enseña extracto y NO se describe como «no hay
        // nada»: se dice qué le pasa, porque son cosas distintas.
        <div className="fuente-error" data-testid="fuente-error">
          <p className="report-p">{t(`source.blocked.${s.estado}` as never)}</p>
          {s.motivo && <p className="report-p report-p--muted">{s.motivo}</p>}
          <p className="report-p report-p--muted">{t("source.blocksApproval")}</p>
        </div>
      )}

      <p className="report-p report-p--muted">{t("source.technicalOnly")}</p>
    </div>
  );
}
