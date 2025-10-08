package com.webpet_nhom20.backdend.common;

import com.webpet_nhom20.backdend.entity.ServiceAppointments;

import java.time.format.DateTimeFormatter;


public class CommonUtil {

    // Mail đặt lịch
	public static String buildAppointmentEmailSubject(ServiceAppointments appointment, String userFullName, String userPhone) {
		return "Xác nhận đặt lịch dịch vụ chăm sóc thú cưng cho anh/chị " + userFullName + " - SĐT: " + (userPhone == null ? "(Không có)" : userPhone);
	}

	public static String buildAppointmentEmailHtml(ServiceAppointments appointment, String userFullName, String userPhone, String serviceName) {
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm dd/MM/yyyy");
		String start = appointment.getAppoinmentStart().format(formatter);
		String end = appointment.getAppoinmentEnd().format(formatter);
		String petName = appointment.getNamePet() == null ? "(Không có)" : appointment.getNamePet();
		String notes = appointment.getNotes() == null ? "(Không có)" : appointment.getNotes();
		String safePhone = userPhone == null ? "(Không có)" : userPhone;

		String shopName = "Pet Shop";
		String supportPhone = "+84 912 345 678";
		String supportEmail = "support@petshop.vn";
		String address = "123 Đường ABC, Thường Tín, TP.Hà Nội";
		String logoUrl = "https://i.imgur.com/9z8ZQWl.png";

		return "<div style=\"font-family:Arial,sans-serif;font-size:14px;color:#1f2937\">" +
			"<div style=\"display:flex;align-items:center;gap:12px;margin-bottom:12px\">" +
				"<h2 style=\"color:#ffc107;margin:0\">" + shopName + "</h2>" +
			"</div>" +
			"<h3 style=\"color:#111827;margin:0 0 12px\">Xác nhận đặt lịch dịch vụ</h3>" +
			"<p>Chào <strong>" + userFullName + "</strong>,</p>" +
			"<p>Bạn đã đặt lịch thành công tại <strong>Pet Shop</strong>. Thông tin chi tiết:</p>" +
			"<table style=\"border-collapse:collapse;width:100%;max-width:560px\">" +
			"<tbody>" +
			row("Dịch vụ", serviceName) +
			row("Họ và tên", userFullName) +
			row("Số điện thoại", safePhone) +
			row("Tên thú cưng", petName) +
			row("Bắt đầu", start) +
			row("Kết thúc", end) +
			row("Ghi chú", notes) +
			"</tbody></table>" +
			"<p style=\"margin-top:16px\">Nếu cần thay đổi lịch hẹn, vui lòng phản hồi email này hoặc liên hệ chúng tôi.</p>" +
			"<div style=\"margin-top:20px;padding-top:12px;border-top:1px solid #e5e7eb;color:#6b7280;font-size:13px\">" +
				"<p style=\"margin:0\"><strong>" + shopName + "</strong></p>" +
				"<p style=\"margin:0\">" + address + "</p>" +
				"<p style=\"margin:0\">Hotline: " + supportPhone + " · Email: " + supportEmail + "</p>" +
			"</div>" +
			"</div>";
	}

	private static String row(String label, String value) {
		return "<tr>" +
			"<td style=\"padding:8px 12px;border:1px solid #e5e7eb;background:#f9fafb;width:30%\"><strong>" + label + "</strong></td>" +
			"<td style=\"padding:8px 12px;border:1px solid #e5e7eb\">" + escapeHtml(value) + "</td>" +
			"</tr>";
	}

	private static String escapeHtml(String input) {
		if (input == null) return "";
		return input
			.replace("&", "&amp;")
			.replace("<", "&lt;")
			.replace(">", "&gt;")
			.replace("\"", "&quot;")
			.replace("'", "&#39;");
	}

	// Mail khác viết ở dưới

}
