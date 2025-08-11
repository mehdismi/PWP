import React, { useContext } from 'react';
import { Navigate } from 'react-router-dom';
import AuthContext from '../auth/AuthContext';
import { CircularProgress, Box } from '@mui/material';

const PrivateRoute = ({ children }) => {
  const { user, loadingUser } = useContext(AuthContext);

  if (loadingUser) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '80vh' }}>
        <CircularProgress size={60} />
      </Box>
    );
  }

  if (!user) {
    return <Navigate to="/v1/login" />;
  }

  return children;
};

export default PrivateRoute;
