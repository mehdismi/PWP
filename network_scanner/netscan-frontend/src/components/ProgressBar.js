import React from 'react';
import { Box, LinearProgress, Typography } from '@mui/material';

const ProgressBar = ({ value }) => {
  return (
    <Box sx={{ width: '100%' }}>
      <LinearProgress variant="determinate" value={value} />
      <Typography variant="caption" display="block" textAlign="center">
        {value}%
      </Typography>
    </Box>
  );
};

export default ProgressBar;
