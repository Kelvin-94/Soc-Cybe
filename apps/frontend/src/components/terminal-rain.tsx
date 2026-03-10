/*
SOC-CyBe Security Platform
Module: Terminal Rain Background

Purpose:
This visual component creates the ambient terminal-style background used by
the SOC dashboard. It is decorative only and does not carry operational data.
*/

const columns = Array.from({ length: 18 }, (_, index) => index);

export function TerminalRain() {
  /* The component is marked as purely decorative so assistive technologies
     do not treat the animated text as meaningful dashboard content. */
  return (
    <div className="terminalRain" aria-hidden="true">
      {columns.map((column) => (
        <span
          key={column}
          className="terminalRain__column"
          style={{
            left: `${column * 5.75}%`,
            animationDelay: `${column * 0.6}s`,
            animationDuration: `${9 + (column % 5)}s`,
          }}
        >
          01001011 SEC SOC API JWT TLS RBAC
        </span>
      ))}
    </div>
  );
}
