Log Analysis

A full-stack asynchronous log analysis application that allows users to securely upload Zscaler-style log files and analyze them using a Flask-based API with Celery background workers.
All parsed logs, job metadata, and analysis results are stored in a PostgreSQL database.

🔗 Live Link

Click here to view the deployed application

Since the application is deployed on the free tier, the initial request may take a few seconds due to backend cold start.
Features
User Authentication

Register and login functionality with hashed password storage.

Session-based authentication using secure cookies.

Protected API endpoints.

Logout support.

Log File Upload

Secure file upload and server-side storage.

Validation of uploaded files.

Uploaded files are queued for asynchronous processing.

Asynchronous Log Analysis

Non-blocking log processing using Celery + Redis.

Background workers parse and analyze logs without blocking API requests.

Job-based execution model with persistent tracking.

Job Tracking

Each analysis request creates a job record.

Job status stored in the database:

Pending

Processing

Completed

Failed

Supports progress tracking and error reporting.

Threat Analysis

Parses Zscaler-style logs.

Identifies blocked events and threats.

Stores structured log data in PostgreSQL.

Enables historical analysis of blocked threats.

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
