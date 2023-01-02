import { Request, Response } from "express";

import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

import { BadRequestError } from "../helpers/api-errors";
import { UserRepository } from "../repositories/userRepository";

export class UserController {
  async create(req: Request, res: Response){
    const { name, email, password, confpassword } = req.body;

    if(!name) {
      throw new BadRequestError('Please insert a name');
    }

    if(!email) {
      throw new BadRequestError('Please insert a email'); 
    }

    const userExists = await UserRepository.findOneBy({ email });

    if(userExists) {
      throw new BadRequestError('Email already Exists');

    }

    if(password != confpassword) {
      throw new BadRequestError('Please insert the same Password and confirm password ')

    }

    const passwordHash = await bcrypt.hash(password, 8);

    const newUser = UserRepository.create({ name, email, password: passwordHash });
    
    await UserRepository.save(newUser);

    const {password: _, ...user } = newUser

    return res.status(201).json(user);
  
  }

  async login(req: Request, res: Response) {
    const { email, password } = req.body;

    if(!email) {
      throw new BadRequestError('Please insert an email');
    }

    if(!password) {
      throw new BadRequestError('Please insert a password'); 
    }

    const user = await UserRepository.findOneBy({ email });

    if(!user) {
      throw new BadRequestError('Please insert Email or password correct');

    }

    const verifyPassword = await bcrypt.compare(password, user.password);

    if(!verifyPassword) {
    throw new BadRequestError('Please insert Email or password correct');
  
    }

    const token = jwt.sign({id: user.id}, process.env.JWT_PASS ?? '', { expiresIn: '1D' } );

    const { password: _, ...userLogin} = user;

    return res.json({ user: userLogin,  token: token })

  }

  async getProfile(req: Request, res: Response) {

    return res.json(req.user);

  }
}