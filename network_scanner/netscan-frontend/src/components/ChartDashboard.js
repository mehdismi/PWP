import React, { useEffect, useState } from 'react';
import axiosInstance from '../api/axiosInstance';
import { Container, Typography, Grid, Paper } from '@mui/material';
import { Bar, Doughnut } from 'react-chartjs-2';
import { Chart, ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend } from 'chart.js';

Chart.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend);

const ChartDashboard = () => {
  const [summary, setSummary] = useState(null);

  const fetchSummary = async () => {
    try {
      const response = await axiosInstance.get('scans/dashboard/summary/');
      setSummary(response.data);
    } catch (error) {
      console.error('Failed to fetch dashboard summary', error);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, []);

  if (!summary) return <div>Loading...</div>;

  const scanNames = summary.scans.map(scan => scan.scan_name);
  const openPortsCounts = summary.scans.map(scan => scan.open_ports_count);
  const servicesCounts = {};

  summary.scans.forEach(scan => {
    scan.services_list.forEach(service => {
      servicesCounts[service] = (servicesCounts[service] || 0) + 1;
    });
  });

  const servicesLabels = Object.keys(servicesCounts);
  const servicesData = Object.values(servicesCounts);

  return (
    <Container sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom>Scan Dashboard</Typography>

      <Grid container spacing={4}>
        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 4 }}>
            <Typography variant="h6" gutterBottom>Open Ports Per Scan</Typography>
            <Bar
              data={{
                labels: scanNames,
                datasets: [
                  {
                    label: 'Open Ports',
                    data: openPortsCounts,
                    backgroundColor: 'rgba(54, 162, 235, 0.7)',
                  }
                ]
              }}
              options={{
                responsive: true,
                plugins: {
                  legend: { display: false },
                },
              }}
            />
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={3} sx={{ p: 4 }}>
            <Typography variant="h6" gutterBottom>Service Detection</Typography>
            <Doughnut
              data={{
                labels: servicesLabels,
                datasets: [
                  {
                    data: servicesData,
                    backgroundColor: [
                      'rgba(255, 99, 132, 0.7)',
                      'rgba(255, 206, 86, 0.7)',
                      'rgba(75, 192, 192, 0.7)',
                      'rgba(153, 102, 255, 0.7)',
                      'rgba(255, 159, 64, 0.7)',
                      'rgba(54, 162, 235, 0.7)',
                    ],
                  }
                ]
              }}
              options={{
                responsive: true,
                plugins: {
                  legend: {
                    position: 'bottom',
                  },
                },
              }}
            />
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
};

export default ChartDashboard;
