import { Router, Request, Response, NextFunction } from 'express';
import { trustSchema } from '../utils/validation';
import { assessTrust } from '../services/trust.service';
import type { TrustRequest } from '../types/index';
export const trustRouter = Router();

trustRouter.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { error, value } = trustSchema.validate(req.body, { abortEarly: false });
    if (error) { res.status(422).json({ error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.details.map(d => d.message) } }); return; }
    res.status(200).json(await assessTrust(value as TrustRequest));
  } catch (err) { next(err); }
});

trustRouter.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const body: TrustRequest = { email: req.query.email as string | undefined, phone: req.query.phone as string | undefined, ip: req.query.ip as string | undefined, wallet_address: req.query.wallet_address as string | undefined, wallet_chain: req.query.wallet_chain as string | undefined as never, country_code: req.query.country_code as string | undefined };
    const { error, value } = trustSchema.validate(body, { abortEarly: false });
    if (error) { res.status(422).json({ error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.details.map(d => d.message) } }); return; }
    res.status(200).json(await assessTrust(value as TrustRequest));
  } catch (err) { next(err); }
});
