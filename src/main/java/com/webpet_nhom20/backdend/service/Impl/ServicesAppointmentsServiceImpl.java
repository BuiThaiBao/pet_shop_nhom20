package com.webpet_nhom20.backdend.service.Impl;

import com.webpet_nhom20.backdend.config.JwtTokenProvider;
import com.webpet_nhom20.backdend.dto.request.ServiceAppointment.CancelServiceAppointmentRequest;
import com.webpet_nhom20.backdend.dto.request.ServiceAppointment.ServiceAppointmentsRequest;
import com.webpet_nhom20.backdend.dto.request.ServiceAppointment.UpdateServiceAppointmentRequest;
import com.webpet_nhom20.backdend.dto.request.ServiceAppointment.UserServiceAppointmentRequest;
import com.webpet_nhom20.backdend.dto.response.ServiceAppointmentsResponse;
import com.webpet_nhom20.backdend.entity.ServiceAppointments;
import com.webpet_nhom20.backdend.entity.ServicesPet;
import com.webpet_nhom20.backdend.common.CommonUtil;
import com.webpet_nhom20.backdend.enums.AppoinmentStatus;
import com.webpet_nhom20.backdend.exception.AppException;
import com.webpet_nhom20.backdend.exception.ErrorCode;
import com.webpet_nhom20.backdend.mapper.ServiceAppointmentMapper;
import com.webpet_nhom20.backdend.repository.ServicesAppointmentsRepository;
import com.webpet_nhom20.backdend.repository.ServicesPetRespository;
import com.webpet_nhom20.backdend.repository.UserRepository;
import com.webpet_nhom20.backdend.service.AsyncEmailService;
import com.webpet_nhom20.backdend.service.EmailService;
import com.webpet_nhom20.backdend.service.ServicesAppointmentsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;


import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class ServicesAppointmentsServiceImpl implements ServicesAppointmentsService {
    @Autowired
    private ServicesPetRespository servicesPetRespository;

    @Autowired
    private ServicesAppointmentsRepository servicesAppointmentsRepository;

    @Autowired
    private ServiceAppointmentMapper serviceAppointmentMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EmailService emailService;

    @Autowired
    AsyncEmailService asyncEmailService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    public ServiceAppointmentsResponse create(ServiceAppointmentsRequest request) {
        ServicesPet servicesPet = servicesPetRespository.findById(request.getServiceId())
                .orElseThrow(() -> new RuntimeException("Service không tồn tại"));

        ServiceAppointments appointment = serviceAppointmentMapper.toEntity(request);
        LocalDateTime appointmentEnd = request.getAppoinmentStart()
                .plusMinutes(servicesPet.getDurationMinutes());

        appointment.setAppoinmentEnd(appointmentEnd);

        ServiceAppointments saved = servicesAppointmentsRepository.save(appointment);
        try {
            userRepository.findById(saved.getUserId().intValue()).ifPresent(user -> {
                String subject = CommonUtil.buildAppointmentEmailSubject(saved, user.getFullName(), user.getPhone());
                String htmlBody = CommonUtil.buildAppointmentEmailHtml(saved, user.getFullName(), user.getPhone(), servicesPet.getTitle());
                asyncEmailService.sendAppointmentEmail(user.getEmail(), subject, htmlBody);
            });
        } catch (Exception ex) {
            // Không chặn luồng chính nếu gửi mail lỗi
        }
        ServiceAppointmentsResponse response = serviceAppointmentMapper.toResponse(saved);

        response.setServiceName(servicesPet.getTitle());

        return response;
    }

    @Override
    public Page<ServiceAppointmentsResponse> getAppointmentsByRole(UserServiceAppointmentRequest request, Pageable pageable) {
        String role = request.getRoleName();

        if(role.equals("SHOP")){
            return servicesAppointmentsRepository.findAllOrderByStatusAndStart(pageable)
                    .map(entity -> {
                        ServiceAppointmentsResponse response = serviceAppointmentMapper.toResponse(entity);
                        servicesPetRespository.findById(entity.getServiceId())
                                .ifPresent(sp -> response.setServiceName(sp.getTitle()));
                        return response;
                    });
        }else if (role.equals("CUSTOMER")){
            return servicesAppointmentsRepository.findByUserIdOrderByStatusAndStart(request.getUserId(), pageable)
                    .map(entity -> {
                        ServiceAppointmentsResponse response = serviceAppointmentMapper.toResponse(entity);
                        servicesPetRespository.findById(entity.getServiceId())
                                .ifPresent(sp -> response.setServiceName(sp.getTitle()));
                        return response;
                    });
        } else {
            throw new RuntimeException("Invalid role " + role );
        }
    }

    @Override
    public ServiceAppointmentsResponse update(UpdateServiceAppointmentRequest request, String token) {
        
        // Validate JWT token và lấy thông tin user
        Integer userIdFromToken = jwtTokenProvider.getUserId(token);
        String roleFromToken = jwtTokenProvider.getUserRole(token);
        
        if (userIdFromToken == null || roleFromToken == null) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
        // Tìm appointment theo ID
        ServiceAppointments existingAppointment = servicesAppointmentsRepository.findById(request.getId())
                .orElseThrow(() -> new AppException(ErrorCode.APPOINTMENT_NOT_FOUND));
        // Kiểm tra quyền truy cập
        if (roleFromToken.equals("CUSTOMER")) {
            // Customer chỉ có thể cập nhật appointment của chính họ
            if (!existingAppointment.getUserId().equals(userIdFromToken.longValue())) {
                throw new AppException(ErrorCode.ACCESS_DENIED);
            }
            
            // Customer không được phép cập nhật status
            if (request.getStatus() != null) {
                log.error("Customer {} trying to update status, which is not allowed", userIdFromToken);
                throw new AppException(ErrorCode.ACCESS_DENIED);
            }

        } else if (roleFromToken.equals("SHOP")) {
            // Shop có thể cập nhật bất kỳ appointment nào
        } else {
            log.error("Invalid role: {}", roleFromToken);
            throw new AppException(ErrorCode.ACCESS_DENIED);
        }
        
        // Validate service tồn tại nếu có thay đổi serviceId
        if (request.getServiceId() != null && !request.getServiceId().equals(existingAppointment.getServiceId())) {
            ServicesPet service = servicesPetRespository.findById(request.getServiceId())
                    .orElseThrow(() -> new AppException(ErrorCode.SERVICE_NOT_FOUND));
        }
        // Cập nhật thông tin appointment
        if (request.getNamePet() != null) {
            existingAppointment.setNamePet(request.getNamePet());
        }
        
        if (request.getSpeciePet() != null) {
            existingAppointment.setSpeciePet(request.getSpeciePet());
        }
        
        if (request.getAppoinmentStart() != null) {
            existingAppointment.setAppoinmentStart(request.getAppoinmentStart());
            
            // Cập nhật appointment_end nếu có thay đổi serviceId hoặc start time
            int serviceId = request.getServiceId() != null ? request.getServiceId() : existingAppointment.getServiceId();
            ServicesPet service = servicesPetRespository.findById(serviceId)
                    .orElseThrow(() -> new AppException(ErrorCode.SERVICE_NOT_FOUND));
            
            LocalDateTime appointmentEnd = request.getAppoinmentStart()
                    .plusMinutes(service.getDurationMinutes());
            existingAppointment.setAppoinmentEnd(appointmentEnd);
        }
        
        if (request.getServiceId() != null && !request.getServiceId().equals(existingAppointment.getServiceId())) {
            existingAppointment.setServiceId(request.getServiceId());
            
            // Cập nhật lại appointment_end khi service thay đổi
            if (request.getAppoinmentStart() != null) {
                ServicesPet service = servicesPetRespository.findById(request.getServiceId())
                        .orElseThrow(() -> new AppException(ErrorCode.SERVICE_NOT_FOUND));
                
                LocalDateTime appointmentEnd = request.getAppoinmentStart()
                        .plusMinutes(service.getDurationMinutes());
                existingAppointment.setAppoinmentEnd(appointmentEnd);
            }
        }
        
        // Chỉ SHOP mới được cập nhật status
        if (request.getStatus() != null && roleFromToken.equals("SHOP")) {
            existingAppointment.setStatus(request.getStatus());
            log.info("Status updated to: {}", request.getStatus());
        }
        
        if (request.getNotes() != null) {
            existingAppointment.setNotes(request.getNotes());
        }
        
        // Lưu appointment đã cập nhật
        ServiceAppointments savedAppointment = servicesAppointmentsRepository.save(existingAppointment);
        
        // Tạo response
        ServiceAppointmentsResponse response = serviceAppointmentMapper.toResponse(savedAppointment);
        
        // Lấy tên service để hiển thị trong response
        servicesPetRespository.findById(savedAppointment.getServiceId())
                .ifPresent(service -> response.setServiceName(service.getTitle()));
        
        return response;
    }

    @Override
    public ServiceAppointmentsResponse cancel(CancelServiceAppointmentRequest request, String token) {

        // 1️⃣ Xác thực token
        Integer userIdFromToken = jwtTokenProvider.getUserId(token);
        if (userIdFromToken == null) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }

        // 2️⃣ Lấy appointment từ DB
        ServiceAppointments existingAppointment = servicesAppointmentsRepository.findById(request.getId())
                .orElseThrow(() -> new AppException(ErrorCode.APPOINTMENT_NOT_FOUND));
        if(!existingAppointment.getUserId().equals(userIdFromToken.longValue())){
            throw new AppException(ErrorCode.UNAUTHENTICATED_CANCEL);
        }
        // 3️⃣ Kiểm tra nếu đã bị hủy trước đó
        if (existingAppointment.getStatus() == AppoinmentStatus.CANCELED) {
            throw new AppException(ErrorCode.ALREADY_CANCELED);
        }
        if (existingAppointment.getStatus() == AppoinmentStatus.COMPLETED) {
            throw new AppException(ErrorCode.ALREADY_COMPLETED);
        }


        // 4️⃣ Cập nhật trạng thái "CANCELED"
        existingAppointment.setStatus(AppoinmentStatus.CANCELED);
        existingAppointment.setNotes("Cuộc hẹn đã bị hủy lúc " + LocalDateTime.now());

        // 5️⃣ Lưu lại vào DB
        ServiceAppointments canceledAppointment = servicesAppointmentsRepository.save(existingAppointment);

        // 6️⃣ Mapping sang response
        ServiceAppointmentsResponse response = serviceAppointmentMapper.toResponse(canceledAppointment);


        return response;
    }

}
