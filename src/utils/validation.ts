import Joi from 'joi';
export const trustSchema = Joi.object({
  email: Joi.string().optional(),
  phone: Joi.string().optional(),
  ip: Joi.string().optional(),
  wallet_address: Joi.string().optional(),
  wallet_chain: Joi.string().valid('ethereum', 'solana', 'bnb', 'xrp', 'auto').default('auto'),
  country_code: Joi.string().length(2).uppercase().optional(),
}).or('email', 'phone', 'ip', 'wallet_address').messages({
  'object.missing': 'At least one of email, phone, ip or wallet_address is required',
});
