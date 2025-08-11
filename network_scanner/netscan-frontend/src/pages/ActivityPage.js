import React, { useEffect, useState } from 'react';
import axiosInstance from '../api/axiosInstance';
import {
  Container,
  Typography,
  Paper,
  List,
  ListItem,
  ListItemText
} from '@mui/material';

const ActivityPage = () => {
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchActivities = async () => {
    try {
      const response = await axiosInstance.get('accounts/activity/');
      setActivities(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch activities', error);
    }
  };

  useEffect(() => {
    fetchActivities();
  }, []);

  if (loading) return <div>Loading...</div>;

  return (
    <Container sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom>Activity Log</Typography>

      <Paper elevation={3} sx={{ p: 4 }}>
        {activities.length === 0 ? (
          <Typography>No activities found.</Typography>
        ) : (
          <List>
            {activities.map((activity) => (
              <ListItem key={activity.id} divider>
                <ListItemText
                  primary={activity.action}
                  secondary={new Date(activity.timestamp).toLocaleString()}
                />
              </ListItem>
            ))}
          </List>
        )}
      </Paper>
    </Container>
  );
};

export default ActivityPage;
