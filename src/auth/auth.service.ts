import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

import * as bcrypt from 'bcrypt';

import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { error } from 'console';
import { envs } from 'src/config';
import { RpcException } from '@nestjs/microservices';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }

  //METODO PARA GENERAR TOKEN
  async sygnJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      }); // Verificamos que el token sea valido

      //Retornamos el user y el nuevo token
      return {
        user: user,
        token: await this.sygnJWT(user),
      };
    } catch (error) {
      console.log(error);
      throw new RpcException({
        status: 401,
        message: 'Invalid token',
      });
    }
  }

  //METODO PARA REGISTRAR USUARIOS
  async registerUser(registerUser: RegisterUserDto) {
    //Desestructuracion de datos
    const { name, email, password } = registerUser;

    try {
      //Verificamos si el email existe
      const user = await this.user.findUnique({
        where: {
          email: email,
        },
      });

      if (user) {
        throw new Error(`Email already exists`);
      }

      //Creamos en base de datos el usuario
      const newUser = await this.user.create({
        data: {
          email: email,
          password: bcrypt.hashSync(password, 10), //hashear password
          name: name,
        },
      });

      const { password: __, ...rest } = newUser; //Separamos el password de la data que vamos a retornar
      return {
        user: rest,
        token: await this.sygnJWT(rest),
      };
    } catch (error) {
      throw new Error(error);
    }
  }

  //METODO PARA LOGUEAR USUARIOS
  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      //Verificamos si el email existe
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });

      if (!user) {
        throw new Error(`User/Password not found`);
      }

      const isPasswordValid = bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        throw new error('User/Password not found');
      }

      const { password: __, ...rest } = user; //Separamos el password de la data que vamos a retornar
      return {
        user: rest,
        token: await this.sygnJWT(rest),
      };
    } catch (error) {
      throw new Error(error);
    }
  }
}
