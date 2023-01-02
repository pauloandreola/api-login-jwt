import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

import { BadRequestError, UnauthorizedError } from "../helpers/api-errors";
import { UserRepository } from "../repositories/userRepository";

type JwtPayload = {
  id: number;
};

export const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  const { authorization } = req.headers;

  if(!authorization) {
    throw new UnauthorizedError('Not authorized')
  }

  const token = authorization.split(' ')[1];

  const { id } = jwt.verify(token, process.env.JWT_PASS ?? '') as JwtPayload

  const user = await UserRepository.findOneBy({ id });

  if(!user) {
    throw new BadRequestError('Please insert Email or password correct');

  }

  const { password: _, ... loggedUser} = user;

  req.user = loggedUser;

  next();

}