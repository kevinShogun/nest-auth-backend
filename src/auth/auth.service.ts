import { RegisterDto } from './dto/register.dto';
import { Injectable, BadRequestException, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';
import * as bcryptjs from "bcryptjs";
import { LoginDto } from './dto/login.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';


@Injectable()
export class AuthService {

    constructor(
        @InjectModel(User.name)
        private userModel: Model<User>,
        private jwtService: JwtService
    ) { }

    async create(createUserDto: CreateUserDto): Promise<User> {

        try {

            // 1 Encriptar pass
            const { password, ...userData } = createUserDto;
            const newUser = new this.userModel({
                password: bcryptjs.hashSync(password, 10),
                ...userData
            });

            // 2 Guardar user
            await newUser.save();
            const { password: _, ...userReturn } = newUser.toJSON();

            return userReturn;

        } catch (error) {
            if (error.code === 11000) {
                throw new BadRequestException(`${createUserDto.email} already exists!`)
            }
            throw new InternalServerErrorException('Something error exists')
        }



    }

    async register(registerDto: RegisterDto): Promise<LoginResponse> {
        const userData = await this.create(registerDto);

        return {
            user: { ...userData },
            token: this.getJwtToken({ id: userData._id })
        };
    }

    async login(loginDto: LoginDto): Promise<LoginResponse> {

        const { email, password } = loginDto;

        const user = await this.userModel.findOne({ email });
        if (!user) {
            throw new UnauthorizedException('Not valid credentials - email')
        }

        if (!bcryptjs.compareSync(password, user.password)) {
            throw new UnauthorizedException('Not valid credentials - password')
        }

        const { password: _, ...userData } = user.toJSON();

        return {
            user: { ...userData },
            token: this.getJwtToken({ id: user.id })
        };
    }

    findAll(): Promise<User[]> {
        return this.userModel.find();
    }

    async findUserById(id: string) {
        const user = await this.userModel.findById(id);
        const { password, ...rest } = user.toJSON();
        return rest;
    }

    async validateToken(user: User): Promise<LoginResponse> {
        return {
            user,
            token: this.getJwtToken({ id: user._id })
        };
    }


    findOne(id: number) {
        return `This action returns a #${id} auth`;
    }

    update(id: number, updateAuthDto: UpdateAuthDto) {
        return `This action updates a #${id} auth`;
    }

    remove(id: number) {
        return `This action removes a #${id} auth`;
    }

    getJwtToken(payload: JwtPayload) {
        const token = this.jwtService.sign(payload);
        return token;
    }
}
