## InsightOps – Incident Triage Dashboard

<dashboard version="1.1" refresh="60">
  <label>InsightOps - Incident Triage</label>
  <description>
    Tier-1 / Tier-2 analyst triage queue for AI-enriched incidents
  </description>

  <!-- TIME RANGE -->
  <fieldset submitButton="false">
    <input type="dropdown" token="time_range">
      <label>Time Range</label>
      <choice value="-15m">Last 15 minutes</choice>
      <choice value="-1h">Last 1 hour</choice>
      <choice value="-24h">Last 24 hours</choice>
      <choice value="-7d">Last 7 days</choice>
      <default>-7d</default>
    </input>
  </fieldset>

  <!-- INCIDENT TABLE -->
  <row>
    <panel>
      <title>Incident Queue (Auto-refresh: 1 min)</title>

      <table>
        <search>
          <query><![CDATA[
index=ai_soc sourcetype=ai:soc:incident earliest=$time_range$
| eval incident_id = coalesce(incident_id, event.incident_id)
| eval risk_score  = coalesce(risk_score, event.risk_score)
| eval host        = coalesce(host, event.host)

| eval explanation = coalesce(
    plain_english_summary,
    risk_score_explanation,
    "No explanation available"
)

| spath path=mitre_techniques{}.technique_id output=mitre_id
| spath path=mitre_techniques{}.technique_name output=mitre_name
| eval mitre_pair = mvzip(mitre_id, mitre_name, " — ")

| spath path=alerts{}.alert_id output=alert_ids

| eval user = "UNKNOWN"

| stats
    latest(_time)        AS _time
    max(risk_score)     AS risk_score
    values(host)        AS host
    values(user)        AS user
    values(alert_ids)   AS alert_ids
    values(mitre_pair)  AS mitre_technique
    values(explanation) AS explanation
  BY incident_id

| eval risk_level = case(
    risk_score >= 90, "CRITICAL",
    risk_score >= 75, "HIGH",
    risk_score >= 40, "MEDIUM",
    1=1, "LOW"
)

| eval mitre_technique = mvjoin(mitre_technique, ", ")
| eval explanation     = mvjoin(explanation, " ")
| eval risk_score      = round(risk_score, 2)

| table _time incident_id risk_score risk_level host user mitre_technique explanation
| sort - _time
          ]]></query>
        </search>

        <!-- TABLE OPTIONS -->
        <option name="wrap">true</option>
        <option name="rowNumbers">true</option>
        <option name="count">15</option>

        <!-- RISK LEVEL COLORING -->
        <format type="color" field="risk_level">
          <colorPalette type="map">
            <map value="CRITICAL">#8b0000</map>
            <map value="HIGH">#ff4d4d</map>
            <map value="MEDIUM">#ffa64d</map>
            <map value="LOW">#7fdc8c</map>
          </colorPalette>
        </format>

        <!-- INCIDENT → RAW ALERT DRILLDOWN -->
        <drilldown>
          <condition field="incident_id">
            <link><![CDATA[
/app/search/search?q=
index=ai_soc sourcetype=ai:soc:alert
| where incident_id="$row.incident_id$"
| table _time alert_id alert_name severity host
| sort - _time
&earliest=$time_range$
            ]]></link>
          </condition>
        </drilldown>

      </table>
    </panel>
  </row>
</dashboard>


## InsightOps – AI Incident Overview Dashboard

<dashboard version="1.1" refresh="60">
  <label>InsightOps – AI Incident Overview</label>
  <description>
    SOC-wide situational awareness dashboard showing AI-enriched incidents,
    risk distribution, and active MITRE ATT&amp;CK techniques.
  </description>

  <!-- Time Picker -->
  <fieldset submitButton="false">
    <input type="time" token="time_range">
      <label>Time Range</label>
      <default>
        <earliest>-24h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>

  <!-- KPI Row -->
  <row>
    <panel>
      <title>Total Incidents</title>
      <single>
        <search>
          <query>
            index=ai_soc
            earliest=$time_range.earliest$
            latest=$time_range.latest$
            | stats count
          </query>
        </search>
      </single>
    </panel>

    <panel>
      <title>High-Risk Incidents (Risk ≥ 75)</title>
      <single>
        <search>
          <query>
            index=ai_soc
            earliest=$time_range.earliest$
            latest=$time_range.latest$
            | where risk_score &gt;= 75
            | stats count AS high_risk
          </query>
        </search>
        <option name="useColors">true</option>
        <option name="colorBy">value</option>
        <option name="rangeValues">[5,10]</option>
        <option name="rangeColors">["#65A637","#F7BC38","#D93F3C"]</option>
      </single>
    </panel>
  </row>

  <!-- Risk Distribution -->
  <row>
    <panel>
      <title>Incident Distribution by Risk Level</title>
      <chart>
        <search>
          <query>
            index=ai_soc
            earliest=$time_range.earliest$
            latest=$time_range.latest$
            | eval risk_level=case(
                risk_score &gt;= 75,"High",
                risk_score &gt;= 40,"Medium",
                1=1,"Low"
              )
            | stats count by risk_level
          </query>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>

  <!-- MITRE -->
  <row>
    <panel>
      <title>Active MITRE ATT&amp;CK Techniques (Click to Investigate)</title>
      <chart>
        <search>
          <query>
            index=ai_soc
            earliest=$time_range.earliest$
            latest=$time_range.latest$
            | spath path=mitre_techniques{}.technique_id output=mitre_id
            | eval mitre_id=coalesce(mitre_id, mitre_technique, "Unknown")
            | mvexpand mitre_id
            | stats count by mitre_id
            | sort - count
          </query>
        </search>
        <option name="charting.chart">bar</option>
        <drilldown>
          <link><![CDATA[
            search?q=index=ai_soc (
              mitre_techniques{}.technique_id="$click.value$"
              OR mitre_technique="$click.value$"
            )
          ]]></link>
        </drilldown>
      </chart>
    </panel>
  </row>
</dashboard>