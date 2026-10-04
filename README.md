<h1>Log Analysis</h1>

<p>
A full-stack <strong>asynchronous log analysis application</strong> that allows users to securely upload
<strong>Zscaler-style log files</strong> and analyze them using a <strong>Flask-based API</strong> with
<strong>Celery background workers</strong>.
All parsed logs, job metadata, and analysis results are stored in a
<strong>PostgreSQL</strong> database.
</p>

<hr />

<h2>Tech Stack</h2>
<ul>
  <li><strong>Backend:</strong> Flask, Celery</li>
  <li><strong>Messaging / Queue:</strong> Redis (Celery jobs), Apache Kafka (log event streaming)</li>
  <li><strong>Database:</strong> PostgreSQL</li>
  <li><strong>Authentication:</strong> Session-based authentication</li>
</ul>

<hr />

<h2>User Authentication</h2>
<ul>
  <li>Secure user registration and login with <strong>hashed password storage</strong></li>
  <li><strong>Session-based authentication</strong> using secure cookies</li>
  <li><strong>Protected API endpoints</strong> for authenticated users</li>
  <li>Logout support</li>
</ul>

<hr />

<h2>Log File Upload</h2>
<ul>
  <li>Secure file upload with server-side storage</li>
  <li>Validation of uploaded files</li>
  <li>Uploaded logs are <strong>queued for asynchronous processing</strong></li>
</ul>

<hr />

<h2>Asynchronous Log Analysis</h2>
<ul>
  <li><strong>Non-blocking log processing</strong> using <strong>Celery + Redis</strong></li>
  <li>Background workers parse and analyze logs independently of API requests</li>
  <li>API remains responsive while long-running jobs execute</li>
  <li>Architecture designed for <strong>scalability and fault isolation</strong></li>
</ul>

<hr />

<h2>Job Tracking &amp; Monitoring</h2>
<ul>
  <li>Each analysis request creates a <strong>unique job record</strong></li>
  <li>Job metadata stored persistently in PostgreSQL</li>
  <li>Supported job states:</li>
  <ul>
    <li><strong>Pending</strong></li>
    <li><strong>Processing</strong></li>
    <li><strong>Completed</strong></li>
    <li><strong>Failed</strong></li>
  </ul>
  <li>Supports <strong>progress tracking</strong> and <strong>error reporting</strong></li>
</ul>

<hr />

<h2>Kafka Streaming Pipeline</h2>
<pre><code>File upload ──► Celery task ─┐
                             ├──► topic: zscaler.logs.raw ──┬──► consumer_storage.py ──► PostgreSQL (batch insert, job progress)
POST /ingest (API key) ──────┘                              └──► consumer_threats.py ──► topic: threat.alerts ──► GET /alerts/stream (SSE) ──► live UI
</code></pre>
<ul>
  <li>Uploaded files and live log sources go through the <strong>same pipeline</strong></li>
  <li>Messages are keyed by <strong>source IP</strong>, so events from one host stay in order</li>
  <li>Offsets are committed only after work is done (<strong>at-least-once</strong>): if Postgres is down, events wait in Kafka</li>
  <li>A job is <strong>Completed</strong> once <code>processed_events</code> reaches <code>total_events</code></li>
  <li>Consumer lag is exported to Prometheus via <code>kafka-exporter</code> (<code>kafka_consumergroup_lag</code>)</li>
</ul>

<h3>Running</h3>
<pre><code>docker compose up -d            # Kafka, Kafka UI (localhost:8081), kafka-exporter, Prometheus, Grafana
redis-server                    # Celery broker
cd log-analyzer-backend
python app.py
celery -A tasks worker --loglevel=info --pool=solo   # --pool=solo on Windows
python consumer_storage.py
python consumer_threats.py
</code></pre>

<h3>Environment variables</h3>
<ul>
  <li><code>KAFKA_BOOTSTRAP_SERVERS</code> (default <code>localhost:9092</code>)</li>
  <li><code>INGEST_API_KEY</code>: required to enable <code>POST /ingest</code></li>
  <li>Optional: <code>KAFKA_RAW_LOGS_TOPIC</code>, <code>KAFKA_THREAT_ALERTS_TOPIC</code>, <code>KAFKA_TOPIC_PARTITIONS</code></li>
</ul>

<hr />

<h2>Threat Analysis</h2>
<ul>
  <li>Parses <strong>Zscaler-style security logs</strong></li>
  <li>Identifies <strong>blocked events</strong> and known threats</li>
  <li>Stores structured log data in PostgreSQL for efficient querying</li>
  <li>Enables <strong>historical threat analysis</strong> from stored logs</li>
</ul>

<hr />

<h2>Authentication</h2> <h3>POST /register</h3> <p>Register a new user.</p>

<strong>Payload:</strong>

<pre><code class="language-json"> { "username": "user1", "password": "pass123" } </code></pre> <hr> <h3>POST /login</h3> <p>Login a user.</p>

<strong>Payload:</strong>

<pre><code class="language-json"> { "username": "user1", "password": "pass123" } </code></pre>

<strong>Response:</strong>

<ul> <li><strong>Status:</strong> 200 OK</li> <li><strong>Sets:</strong> Session cookie for authentication</li> <li><strong>Message:</strong> "Login successful" or appropriate error message</li> </ul> <hr> <h3>GET /check-auth</h3> <p>Check if the user is currently logged in.</p>

<strong>Example Response:</strong>

<pre><code class="language-json"> { "loggedIn": true, "user": "user1" } </code></pre> <ul> <li><strong>loggedIn:</strong> <code>true</code> if authenticated</li> <li><strong>user:</strong> Current logged-in username</li> </ul>
<h2>Log Upload & Asynchronous Analysis</h2> <h3>POST /upload</h3> <p>Upload a <code>.txt</code> log file.</p>

<strong>Form-Data:</strong>

<pre><code>file: &lt;your_file.txt&gt;</code></pre>

<strong>Response:</strong>

<pre><code class="language-json"> { "filename": "your_file.txt" } </code></pre> <hr> <h3>POST /analyze-zscaler</h3> <p> Queues the uploaded log file for <strong>asynchronous background analysis</strong>. The API immediately returns a job ID while the log is processed by a Celery worker. </p>

<strong>Payload:</strong>

<pre><code class="language-json"> { "filename": "your_file.txt" } </code></pre>

<strong>Response:</strong>

<pre><code class="language-json"> { "job_id": "7e51b456-5359-4000-b01b-bd1b5ac56327", "status": "Processing" } </code></pre> <ul> <li>The request returns immediately</li> <li>Log parsing happens asynchronously in the background</li> </ul> <hr> <h3>GET /job-status/&lt;job_id&gt;</h3> <p>Check the status and progress of an analysis job.</p>

<strong>Response:</strong>

<pre><code class="language-json"> { "status": "Completed", "progress": 100, "error": null } </code></pre> <ul> <li><strong>status:</strong> Pending / Processing / Completed / Failed</li> <li><strong>progress:</strong> Percentage of completion</li> <li><strong>error:</strong> Error message if the job failed</li> </ul> <hr> <h3>GET /analyze-db-logs</h3> <p>Fetch blocked threats from logs already stored in the database.</p>

<strong>Response:</strong>

<pre><code class="language-json"> [ { "Action": "Blocked", "Threat_Name": "Malware" // ... } ] </code></pre> <ul> <li>Returns historical blocked events</li> <li>Data is fetched directly from PostgreSQL</li> </ul>
<hr>
<h3>POST /ingest</h3> <p>Stream log lines into Kafka from machines or log shippers. Authenticated with the <code>X-API-Key</code> header (value of <code>INGEST_API_KEY</code>), not a session.</p>

<strong>Body:</strong> <code>text/plain</code> with one Zscaler CSV line per line, or JSON:

<pre><code class="language-json"> { "lines": ["\"Mon May 05 10:15:23 2025\",\"alice\",..."] } </code></pre>

<strong>Response (202):</strong>

<pre><code class="language-json"> { "accepted": 98, "rejected": 2 } </code></pre> <ul> <li>At most 10,000 lines per request</li> <li>Returns 503 if Kafka is unreachable</li> </ul>
<hr>
<h3>GET /alerts/stream</h3> <p>Server-Sent Events stream of live threat alerts (requires login). Each <code>data:</code> message is a parsed log event with a non-empty threat.</p>
