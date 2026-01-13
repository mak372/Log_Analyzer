import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './FileUpload.css';
import { useNavigate } from 'react-router-dom';

const FileUpload: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [uploadMessage, setUploadMessage] = useState('');
  const [filename, setFilename] = useState('');
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [dbLogs, setDbLogs] = useState<any[]>([]);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const navigate = useNavigate();
  const [jobId, setJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<string | null>(null);

  
  // Check if user is authenticated
  useEffect(() => {
  const checkAuth = async () => {
    try {
      const res = await axios.get('http://localhost:5000/check-auth', {
        withCredentials: true
      });
      console.log(res.data); // Check if loggedIn is true
      if (res.data.loggedIn) {
        setIsAuthenticated(true);
      }
    } catch (err) {
      console.log(err);
      setIsAuthenticated(false);
    }
  };
  checkAuth();
}, []);

// Async logic
useEffect(() => {
  if (!jobId) return;

  const interval = setInterval(async () => {
    try {
      const res = await axios.get(
        `http://localhost:5000/job-status/${jobId}`,
        { withCredentials: true }
      );

      setJobStatus(res.data.status);

      if (res.data.status === 'Completed') {
        clearInterval(interval);

        // Fetch final analysis
        const finalRes = await axios.get(
          'http://localhost:5000/analyze-db-logs',
          { withCredentials: true }
        );

        setAnalysisResult(finalRes.data);
      }

      if (res.data.status === 'Failed') {
        clearInterval(interval);
        alert(res.data.error || 'Job failed');
      }
    } catch (err) {
      clearInterval(interval);
      console.error(err);
    }
  }, 2000);

  return () => clearInterval(interval);
}, [jobId]);



  // Show loading while checking auth
  if (isAuthenticated === null) {
    return <div>Checking authentication...</div>;
  }

  // Redirect if not logged in
  if (isAuthenticated === false) {
    navigate('/');
    return null;
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post('http://localhost:5000/upload', formData, { withCredentials: true });
      setUploadMessage(response.data.message);
      setFilename(response.data.filename);
    } catch (error: any) {
      setUploadMessage(error.response?.data?.message || 'Upload failed');
    }
  };

  const handleAnalyze = async () => {
    if (!filename) return;

    try {
      const response = await axios.post('http://localhost:5000/analyze-zscaler', { filename }, { withCredentials: true });
      //setAnalysisResult(response.data);
      setJobStatus(response.data.status);
      setJobId(response.data.job_id);
    } catch (error: any) {
      alert('Analysis failed: ' + (error.response?.data?.error || 'Unknown error'));
    }
  };

  const handleDbAnalyze = async () => {
    try {
      const response = await axios.get('http://localhost:5000/analyze-db-logs', { withCredentials: true });
      setDbLogs(response.data);
    } catch (error: any) {
      alert('DB log analysis failed: ' + (error.response?.data?.error || 'Unknown error'));
    }
  };

    const handleLogout = async () => {
    try {
     await axios.post('http://localhost:5000/logout', {}, { withCredentials: true });
      setIsAuthenticated(false);
      navigate('/');
    } catch (error) {
      console.error('Logout failed', error);
    }
  };

  return (
    <div className="upload-container">
       <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button onClick={handleLogout}>Logout</button>
      </div>
      <h2>Upload a Log File</h2>
      <input type="file" onChange={handleFileChange} />
      <button onClick={handleUpload}>Upload</button>
      <p>{uploadMessage}</p>
      {
        filename && 
        (
          <div>
            <button onClick={handleAnalyze} disabled={jobStatus === 'Pending' || jobStatus === 'Processing'}>
              Analyze
            </button>
          </div>
        )
      }

      <div>
        <button onClick={handleDbAnalyze}>View past events that were blocked</button>
      </div>
      {
      analysisResult && 
      (
        <div className="analysis-result">
          <h3>Analysis Summary</h3>
          <div className="summary-cards">
          <div className="card">
            <h4>Total Events</h4>
            <p>{analysisResult.summary?.total_events}</p>
          </div>
          <div className="card">
            <h4>Total Threats</h4>
            <p>{analysisResult.summary?.total_threats}</p>
          </div>
        </div>

        <div className="top-threats">
          <h4>Top Threats</h4>
          <ul>
            {
              Object.entries(analysisResult.summary?.top_threats || {}).map(([threatType, count]: any, index) =>(
              <li key={index}>
                <span className="threat-type">{threatType}</span>: <span className="threat-count">{count}</span>
              </li>
              )
              )
            }
          </ul>
        </div>

    <h4>Blocked Threats</h4>
    <table className="threat-table">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>User</th>
          <th>URL</th>
          <th>Threat</th>
        </tr>
      </thead>
      <tbody>
       {Array.isArray(analysisResult?.blocked_threats) && analysisResult.blocked_threats.map((threat: any, index: number) => (
    <tr key={index}>
      <td>{threat.timestamp}</td>
      <td>{threat.user}</td>
      <td>{threat.url}</td>
      <td>{threat.threat}</td>
    </tr>
      ))}
      </tbody>
    </table>

    {analysisResult.note && <p className="note"><strong>Note:</strong> {analysisResult.note}</p>}
  </div>
)}{dbLogs.length > 0 && (
  <div>
    <h3>Previous log events that were blocked</h3>
    <table border = {1} cellPadding= {8} cellSpacing={0}>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>URL</th>
          <th>Source IP</th>
          <th>Threat</th>
        </tr>
      </thead>
      <tbody>
        {dbLogs.map((log, index) => (
          <tr key={index}>
            <td>{log.timestamp}</td>
            <td>{log.url}</td>
            <td>{log.source_ip}</td>
            <td>{log.threat}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
  
)}
    </div>
    
  );
};

export default FileUpload;
