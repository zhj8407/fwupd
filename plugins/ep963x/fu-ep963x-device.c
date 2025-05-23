/*#
 * Copyright 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include "fu-ep963x-common.h"
#include "fu-ep963x-device.h"
#include "fu-ep963x-firmware.h"
#include "fu-ep963x-struct.h"

struct _FuEp963xDevice {
	FuHidDevice parent_instance;
};

G_DEFINE_TYPE(FuEp963xDevice, fu_ep963x_device, FU_TYPE_HID_DEVICE)

#define FU_EP963_DEVICE_TIMEOUT 5000 /* ms */

static gboolean
fu_ep963x_device_write(FuEp963xDevice *self,
		       guint8 ctrl_id,
		       guint8 cmd,
		       const guint8 *buf,
		       gsize bufsz,
		       GError **error)
{
	guint8 bufhw[FU_EP963_FEATURE_ID1_SIZE] = {
	    ctrl_id,
	    cmd,
	    0x0,
	};
	if (buf != NULL) {
		if (!fu_memcpy_safe(bufhw,
				    sizeof(bufhw),
				    0x02, /* dst */
				    buf,
				    bufsz,
				    0x0, /* src */
				    bufsz,
				    error))
			return FALSE;
	}
	if (!fu_hid_device_set_report(FU_HID_DEVICE(self),
				      0x00,
				      bufhw,
				      sizeof(bufhw),
				      FU_EP963_DEVICE_TIMEOUT,
				      FU_HID_DEVICE_FLAG_IS_FEATURE,
				      error))
		return FALSE;

	/* wait for hardware */
	fu_device_sleep(FU_DEVICE(self), 100);
	return TRUE;
}

static gboolean
fu_ep963x_device_write_icp(FuEp963xDevice *self,
			   guint8 cmd,
			   const guint8 *buf,
			   gsize bufsz,
			   guint8 *bufout,
			   gsize bufoutsz,
			   GError **error)
{
	/* wait for hardware */
	for (guint i = 0; i < 5; i++) {
		guint8 bufhw[FU_EP963_FEATURE_ID1_SIZE] = {
		    FU_EP963_USB_CONTROL_ID,
		    cmd,
		};
		if (!fu_ep963x_device_write(self, FU_EP963_USB_CONTROL_ID, cmd, buf, bufsz, error))
			return FALSE;
		if (!fu_hid_device_get_report(FU_HID_DEVICE(self),
					      0x00,
					      bufhw,
					      sizeof(bufhw),
					      FU_EP963_DEVICE_TIMEOUT,
					      FU_HID_DEVICE_FLAG_IS_FEATURE,
					      error)) {
			return FALSE;
		}
		if (bufhw[2] == FU_EP963_USB_STATE_READY) {
			/* optional data */
			if (bufout != NULL) {
				if (!fu_memcpy_safe(bufout,
						    bufoutsz,
						    0x0,
						    bufhw,
						    sizeof(bufhw),
						    0x02,
						    bufoutsz,
						    error))
					return FALSE;
			}
			return TRUE;
		}
		g_debug("SMBUS: %s [0x%x]", fu_ep963x_smbus_error_to_string(bufhw[7]), bufhw[7]);
		fu_device_sleep(FU_DEVICE(self), 100);
	}

	/* failed */
	g_set_error_literal(error, FWUPD_ERROR, FWUPD_ERROR_WRITE, "failed to wait for icp-done");
	return FALSE;
}

static gboolean
fu_ep963x_device_detach(FuDevice *device, FuProgress *progress, GError **error)
{
	FuEp963xDevice *self = FU_EP963X_DEVICE(device);
	const guint8 buf[] = {'E', 'P', '9', '6', '3'};
	g_autoptr(GError) error_local = NULL;

	/* sanity check */
	if (fu_device_has_flag(device, FWUPD_DEVICE_FLAG_IS_BOOTLOADER)) {
		g_debug("already in bootloader mode, skipping");
		return TRUE;
	}

	if (!fu_ep963x_device_write_icp(self,
					FU_EP963_ICP_ENTER,
					buf,
					sizeof(buf), /* in */
					NULL,
					0x0, /* out */
					&error_local)) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_WRITE,
			    "failed to detach: %s",
			    error_local->message);
		return FALSE;
	}

	fu_device_add_flag(device, FWUPD_DEVICE_FLAG_WAIT_FOR_REPLUG);
	return TRUE;
}

static gboolean
fu_ep963x_device_attach(FuDevice *device, FuProgress *progress, GError **error)
{
	FuEp963xDevice *self = FU_EP963X_DEVICE(device);
	g_autoptr(GError) error_local = NULL;

	/* sanity check */
	if (!fu_device_has_flag(device, FWUPD_DEVICE_FLAG_IS_BOOTLOADER)) {
		g_debug("already in runtime mode, skipping");
		return TRUE;
	}
	if (!fu_ep963x_device_write(self,
				    FU_EP963_USB_CONTROL_ID,
				    FU_EP963_OPCODE_SUBMCU_PROGRAM_FINISHED,
				    NULL,
				    0,
				    &error_local)) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_WRITE,
			    "failed to boot to runtime: %s",
			    error_local->message);
		return FALSE;
	}
	fu_device_add_flag(device, FWUPD_DEVICE_FLAG_WAIT_FOR_REPLUG);
	return TRUE;
}

static gboolean
fu_ep963x_device_setup(FuDevice *device, GError **error)
{
	FuEp963xDevice *self = FU_EP963X_DEVICE(device);
	guint8 buf[] = {0x0};
	g_autofree gchar *version = NULL;

	/* FuUsbDevice->setup */
	if (!FU_DEVICE_CLASS(fu_ep963x_device_parent_class)->setup(device, error))
		return FALSE;

	/* get version */
	if (!fu_ep963x_device_write_icp(self,
					FU_EP963_UF_CMD_VERSION,
					NULL,
					0, /* in */
					buf,
					sizeof(buf), /* out */
					error)) {
		return FALSE;
	}
	version = g_strdup_printf("%i", buf[0]);
	fu_device_set_version(device, version);

	/* the VID and PID are unchanged between bootloader modes */
	if (buf[0] == 0x00) {
		fu_device_add_flag(device, FWUPD_DEVICE_FLAG_IS_BOOTLOADER);
	} else {
		fu_device_remove_flag(device, FWUPD_DEVICE_FLAG_IS_BOOTLOADER);
	}

	/* success */
	return TRUE;
}

static gboolean
fu_ep963x_device_wait_cb(FuDevice *device, gpointer user_data, GError **error)
{
	guint8 bufhw[FU_EP963_FEATURE_ID1_SIZE] = {
	    FU_EP963_USB_CONTROL_ID,
	    FU_EP963_OPCODE_SUBMCU_PROGRAM_BLOCK,
	    0xFF,
	};
	if (!fu_hid_device_get_report(FU_HID_DEVICE(device),
				      0x00,
				      bufhw,
				      sizeof(bufhw),
				      FU_EP963_DEVICE_TIMEOUT,
				      FU_HID_DEVICE_FLAG_IS_FEATURE,
				      error)) {
		return FALSE;
	}
	if (bufhw[2] != FU_EP963_USB_STATE_READY) {
		g_set_error_literal(error, FWUPD_ERROR, FWUPD_ERROR_BUSY, "hardware is not ready");
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_ep963x_device_write_firmware(FuDevice *device,
				FuFirmware *firmware,
				FuProgress *progress,
				FwupdInstallFlags flags,
				GError **error)
{
	FuEp963xDevice *self = FU_EP963X_DEVICE(device);
	g_autoptr(GInputStream) stream = NULL;
	g_autoptr(GError) error_local = NULL;
	g_autoptr(FuChunkArray) blocks = NULL;

	/* progress */
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_flag(progress, FU_PROGRESS_FLAG_GUESSED);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 5, "icp");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 95, NULL);

	/* get default image */
	stream = fu_firmware_get_stream(firmware, error);
	if (stream == NULL)
		return FALSE;

	/* reset the block index */
	if (!fu_ep963x_device_write(self,
				    FU_EP963_USB_CONTROL_ID,
				    FU_EP963_OPCODE_SUBMCU_ENTER_ICP,
				    NULL,
				    0,
				    &error_local)) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_WRITE,
			    "failed to reset block index: %s",
			    error_local->message);
		return FALSE;
	}
	fu_progress_step_done(progress);

	/* write each block */
	blocks = fu_chunk_array_new_from_stream(stream,
						FU_CHUNK_ADDR_OFFSET_NONE,
						FU_CHUNK_PAGESZ_NONE,
						FU_EP963_TRANSFER_BLOCK_SIZE,
						error);
	if (blocks == NULL)
		return FALSE;
	for (guint i = 0; i < fu_chunk_array_length(blocks); i++) {
		guint8 buf[] = {i};
		g_autoptr(FuChunkArray) chunks = NULL;
		g_autoptr(FuChunk) chk2 = NULL;
		g_autoptr(GBytes) chk_blob = NULL;

		/* set the block index */
		if (!fu_ep963x_device_write(self,
					    FU_EP963_USB_CONTROL_ID,
					    FU_EP963_OPCODE_SUBMCU_RESET_BLOCK_IDX,
					    buf,
					    sizeof(buf),
					    &error_local)) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_WRITE,
				    "failed to reset block index: %s",
				    error_local->message);
			return FALSE;
		}

		/* 4 byte chunks */
		chk2 = fu_chunk_array_index(blocks, i, error);
		if (chk2 == NULL)
			return FALSE;
		chk_blob = fu_chunk_get_bytes(chk2);
		chunks = fu_chunk_array_new_from_bytes(chk_blob,
						       fu_chunk_get_address(chk2),
						       FU_CHUNK_PAGESZ_NONE,
						       FU_EP963_TRANSFER_CHUNK_SIZE);
		for (guint j = 0; j < fu_chunk_array_length(chunks); j++) {
			g_autoptr(FuChunk) chk = NULL;
			g_autoptr(GError) error_loop = NULL;

			/* prepare chunk */
			chk = fu_chunk_array_index(chunks, j, error);
			if (chk == NULL)
				return FALSE;

			/* copy data and write */
			if (!fu_ep963x_device_write(self,
						    FU_EP963_USB_CONTROL_ID,
						    FU_EP963_OPCODE_SUBMCU_WRITE_BLOCK_DATA,
						    fu_chunk_get_data(chk),
						    fu_chunk_get_data_sz(chk),
						    &error_loop)) {
				g_set_error(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_WRITE,
					    "failed to write 0x%x: %s",
					    (guint)fu_chunk_get_address(chk),
					    error_loop->message);
				return FALSE;
			}
		}

		/* program block */
		if (!fu_ep963x_device_write(self,
					    FU_EP963_USB_CONTROL_ID,
					    FU_EP963_OPCODE_SUBMCU_PROGRAM_BLOCK,
					    buf,
					    sizeof(buf),
					    &error_local)) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_WRITE,
				    "failed to write 0x%x: %s",
				    (guint)fu_chunk_get_address(chk2),
				    error_local->message);
			return FALSE;
		}

		/* wait for program finished */
		if (!fu_device_retry(device, fu_ep963x_device_wait_cb, 5, NULL, error))
			return FALSE;

		/* update progress */
		fu_progress_set_percentage_full(fu_progress_get_child(progress),
						(gsize)i + 1,
						(gsize)fu_chunk_array_length(chunks));
	}
	fu_progress_step_done(progress);

	/* success! */
	return TRUE;
}

static void
fu_ep963x_device_set_progress(FuDevice *self, FuProgress *progress)
{
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_flag(progress, FU_PROGRESS_FLAG_GUESSED);
	fu_progress_add_step(progress, FWUPD_STATUS_DECOMPRESSING, 0, "prepare-fw");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 2, "detach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 94, "write");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 2, "attach");
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 2, "reload");
}

static void
fu_ep963x_device_init(FuEp963xDevice *self)
{
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UNSIGNED_PAYLOAD);
	fu_device_add_protocol(FU_DEVICE(self), "tw.com.exploretech.ep963x");
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_NUMBER);
	fu_device_set_remove_delay(FU_DEVICE(self), FU_DEVICE_REMOVE_DELAY_RE_ENUMERATE);
	fu_device_set_firmware_size(FU_DEVICE(self), FU_EP963_FIRMWARE_SIZE);
	fu_device_set_firmware_gtype(FU_DEVICE(self), FU_TYPE_EP963X_FIRMWARE);
	fu_device_retry_set_delay(FU_DEVICE(self), 100);
}

static void
fu_ep963x_device_class_init(FuEp963xDeviceClass *klass)
{
	FuDeviceClass *device_class = FU_DEVICE_CLASS(klass);
	device_class->write_firmware = fu_ep963x_device_write_firmware;
	device_class->attach = fu_ep963x_device_attach;
	device_class->detach = fu_ep963x_device_detach;
	device_class->setup = fu_ep963x_device_setup;
	device_class->set_progress = fu_ep963x_device_set_progress;
}
