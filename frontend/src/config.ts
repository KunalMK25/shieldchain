/**
 * Central API configuration.
 * In development: points to localhost:8000
 * In production: points to the deployed Render backend URL
 * Set via REACT_APP_API_URL environment variable.
 */
export const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
