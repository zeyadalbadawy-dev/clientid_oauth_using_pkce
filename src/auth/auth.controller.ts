import { Controller, Get, Req, Res, Session } from '@nestjs/common';
import { AuthService } from './auth.service';
import type { Response, Request } from 'express';
import { get } from 'http';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  @Get('google')
  async handleGoogleAuth(@Req() request: Request, @Res() response: Response) {
    const resUrl: URL = await this.authService.googleAuthUrlHandle(
      request.session,
    );
    if (!resUrl) throw new Error('No redirect URL generated');
    return response.redirect(resUrl.href);
  }

  @Get('/google/callback')
  async googleCallback(@Req() request: Request, @Session() session: any) {
    const fullUrl = `${request.protocol}://${request.get('host')}${request.originalUrl}`;
    console.log(`The full URL in google CAllback ${fullUrl}`);
    return await this.authService.handleTheCallback(fullUrl, session);
  }
}
