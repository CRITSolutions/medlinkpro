import { Router } from 'express';

const router = Router();

// Basic API status endpoint
router.get('/', (_req, res) => {
  res.json({
    message: 'MedLinkPro API v1',
    status: 'operational',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: '/auth',
      organizations: '/organizations', 
      patients: '/patients',
      providers: '/providers',
      claims: '/claims',
      payments: '/payments',
      reports: '/reports',
    },
  });
});

// TODO: Add route modules as we create them
// router.use('/auth', authRoutes);
// router.use('/organizations', organizationRoutes);
// router.use('/patients', patientRoutes);
// router.use('/providers', providerRoutes);
// router.use('/claims', claimRoutes);
// router.use('/payments', paymentRoutes);

export { router as apiRoutes };