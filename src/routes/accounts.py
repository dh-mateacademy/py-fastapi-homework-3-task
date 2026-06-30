from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    MessageResponseSchema
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user"
)
async def register(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> UserRegistrationResponseSchema:
    """Register a new user with email and password."""
    try:
        stmt = select(UserModel).where(UserModel.email == user_data.email)
        result = await db.execute(stmt)
        existing_user = result.scalars().first()

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        stmt_group = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        result_group = await db.execute(stmt_group)
        user_group = result_group.scalars().first()

        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during user creation."
            )

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, user_group.id)
        )

        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()

        return UserRegistrationResponseSchema(
            id=cast(int, new_user.id),
            email=new_user.email
        )

    except HTTPException:
        await db.rollback()
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Activate user account"
)
async def activate(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    """Activate a user account using an activation token."""
    stmt = select(UserModel).where(UserModel.email == activation_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    stmt_token = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == cast(int, user.id),
        ActivationTokenModel.token == activation_data.token
    )
    result_token = await db.execute(stmt_token)
    token_record = result_token.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, token_record.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.execute(
        delete(ActivationTokenModel).where(
            ActivationTokenModel.id == cast(int, token_record.id)
        )
    )
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Request password reset token"
)
async def request_password_reset(
    reset_request: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    """Request a password reset token."""
    stmt = select(UserModel).where(
        UserModel.email == reset_request.email,
        UserModel.is_active == True  # noqa: E712
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user:
        stmt_existing = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == cast(int, user.id)
        )
        result_existing = await db.execute(stmt_existing)
        existing_token = result_existing.scalars().first()

        if existing_token:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.id == cast(
                        int, existing_token.id
                    )
                )
            )

        new_reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(new_reset_token)
        await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Complete password reset"
)
async def complete_password_reset(
    reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    """Complete password reset using a token."""
    try:
        stmt = select(UserModel).where(UserModel.email == reset_data.email)
        result = await db.execute(stmt)
        user = result.scalars().first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        stmt_token = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == cast(int, user.id)
        )
        result_token = await db.execute(stmt_token)
        token_record = result_token.scalars().first()

        if (
            not token_record
            or token_record.token != reset_data.token
        ):
            if token_record:
                await db.execute(
                    delete(PasswordResetTokenModel).where(
                        PasswordResetTokenModel.id == cast(
                            int, token_record.id
                        )
                    )
                )
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        expires_at = cast(datetime, token_record.expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= datetime.now(timezone.utc):
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.id == cast(int, token_record.id)
                )
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user.password = reset_data.password
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.id == cast(int, token_record.id)
            )
        )
        await db.commit()

        return MessageResponseSchema(message="Password reset successfully.")

    except HTTPException:
        await db.rollback()
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="User login"
)
async def login(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
) -> UserLoginResponseSchema:
    """Authenticate user and return access and refresh tokens."""
    try:
        stmt = select(UserModel).where(UserModel.email == login_data.email)
        result = await db.execute(stmt)
        user = result.scalars().first()

        if not user or not user.verify_password(login_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )

        access_token = jwt_manager.create_access_token({"user_id": cast(int, user.id)})
        refresh_token = jwt_manager.create_refresh_token(
            {"user_id": cast(int, user.id)},
            expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS)
        )

        refresh_token_record = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )

        db.add(refresh_token_record)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    except HTTPException:
        await db.rollback()
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token"
)
async def refresh_token(
    token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> TokenRefreshResponseSchema:
    """Refresh access token using a refresh token."""
    try:
        decoded_token = jwt_manager.decode_refresh_token(token_data.refresh_token)
        user_id = decoded_token.get("user_id")

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token."
            )

        stmt = select(RefreshTokenModel).where(
            RefreshTokenModel.token == token_data.refresh_token
        )
        result = await db.execute(stmt)
        refresh_token_record = result.scalars().first()

        if not refresh_token_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        stmt_user = select(UserModel).where(UserModel.id == user_id)
        result_user = await db.execute(stmt_user)
        user = result_user.scalars().first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        new_access_token = jwt_manager.create_access_token({"user_id": user_id})

        return TokenRefreshResponseSchema(access_token=new_access_token)

    except HTTPException:
        raise
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )
