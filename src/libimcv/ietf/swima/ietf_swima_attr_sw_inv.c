/*
 * Copyright (C) 2017 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "ietf_swima_attr_sw_inv.h"
#include "swima/swima_record.h"

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <utils/debug.h>


typedef struct private_ietf_swima_attr_sw_inv_t private_ietf_swima_attr_sw_inv_t;

/**
 * Software [Identifier] Inventory
 * see sections 5.8/5.10 of IETF SW Inventory Message and Attributes for PA-TNC
 *
 *                       1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Flags     |           Software Identifier Count           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |               Request ID Copy / Subscription ID               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           EID Epoch                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           Last EID                            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Record Identifier                       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              Data Model Type PEN              |Data Model Type|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Source ID Num |   Reserved    |  Software Identifier Length   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             Software Identifier (Variable Length)             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Software Locator Length    |  Software Locator (Var. Len)  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Software Inventory only
 * see section 5.10 of IETF SW Inventory Message and Attributes for PA-TNC
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                          Record Length                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                   Record (Variable length)                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define IETF_SWIMA_SW_INV_RESERVED	0x00

/**
 * Private data of an ietf_swima_attr_sw_inv_t object.
 */
struct private_ietf_swima_attr_sw_inv_t {

	/**
	 * Public members of ietf_swima_attr_sw_inv_t
	 */
	ietf_swima_attr_sw_inv_t public;

	/**
	 * Vendor-specific attribute type
	 */
	pen_type_t type;

	/**
	 * Length of attribute value
	 */
	size_t length;

	/**
	 * Offset up to which attribute value has been processed
	 */
	size_t offset;

	/**
	 * Current position of attribute value pointer
	 */
	chunk_t value;

	/**
	 * Contains complete attribute or current segment
	 */
	chunk_t segment;

	/**
	 * Noskip flag
	 */
	bool noskip_flag;

	/**
	 * Request ID
	 */
	uint32_t request_id;

	/**
	 * Event ID Epoch
	 */
	uint32_t eid_epoch;

	/**
	 * Last Event ID
	 */
	uint32_t last_eid;

	/**
	 * Attribute flags
	 */
	uint8_t flags;

	/**
	 * Number of unprocessed software inventory evidence records in attribute
	 */
	uint32_t record_count;

	/**
	 * SWID Tag ID Inventory
	 */
	swima_inventory_t *inventory;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

METHOD(pa_tnc_attr_t, get_type, pen_type_t,
	private_ietf_swima_attr_sw_inv_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_ietf_swima_attr_sw_inv_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_ietf_swima_attr_sw_inv_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_ietf_swima_attr_sw_inv_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_ietf_swima_attr_sw_inv_t *this)
{
	bio_writer_t *writer;
	swima_record_t *sw_record;
	chunk_t sw_id, sw_locator, record;
	pen_type_t data_model;
	uint32_t record_id;
	uint8_t source_id;
	enumerator_t *enumerator;

	if (this->value.ptr)
	{
		return;
	}

	writer = bio_writer_create(IETF_SWIMA_SW_INV_MIN_SIZE);
	writer->write_uint8 (writer, this->flags);
	writer->write_uint24(writer, this->inventory->get_count(this->inventory));
	writer->write_uint32(writer, this->request_id);
	writer->write_uint32(writer, this->eid_epoch);
	writer->write_uint32(writer, this->last_eid);

	enumerator = this->inventory->create_enumerator(this->inventory);
	while (enumerator->enumerate(enumerator, &sw_record))
	{
		record_id  = sw_record->get_record_id(sw_record);
		data_model = sw_record->get_data_model(sw_record);
		source_id  = sw_record->get_source_id(sw_record);
		sw_id      = sw_record->get_sw_id(sw_record, &sw_locator);

		writer->write_uint32(writer, record_id);
		writer->write_uint24(writer, data_model.vendor_id);
		writer->write_uint8 (writer, data_model.type);
		writer->write_uint8 (writer, source_id);
		writer->write_uint8 (writer, IETF_SWIMA_SW_INV_RESERVED);
		writer->write_data16(writer, sw_id);
		writer->write_data16(writer, sw_locator);

		if (this->type.type == IETF_ATTR_SW_INVENTORY)
		{
			record = sw_record->get_record(sw_record);
			writer->write_data32(writer, record);
		}
	}
	enumerator->destroy(enumerator);

	this->value = writer->extract_buf(writer);
	this->segment = this->value;
	this->length = this->value.len;
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_ietf_swima_attr_sw_inv_t *this, uint32_t *offset)
{
	bio_reader_t *reader;
	uint32_t data_model_pen, record_id;
	uint8_t  data_model_type, source_id, reserved;
	pen_type_t data_model;
	chunk_t sw_id, sw_locator, record;
	swima_record_t *sw_record;
	status_t status = NEED_MORE;

	if (this->offset == 0)
	{
		if (this->length < IETF_SWIMA_SW_INV_MIN_SIZE)
		{
			DBG1(DBG_TNC, "insufficient data for %N/%N", pen_names, PEN_IETF,
						   ietf_attr_names, this->type.type);
			*offset = this->offset;
			return FAILED;
		}
		if (this->value.len < IETF_SWIMA_SW_INV_MIN_SIZE)
		{
			return NEED_MORE;
		}
		reader = bio_reader_create(this->value);
		reader->read_uint8 (reader, &this->flags);
		reader->read_uint24(reader, &this->record_count);
		reader->read_uint32(reader, &this->request_id);
		reader->read_uint32(reader, &this->eid_epoch);
		reader->read_uint32(reader, &this->last_eid);
		this->offset = IETF_SWIMA_SW_INV_MIN_SIZE;
		this->value = reader->peek(reader);
		reader->destroy(reader);
	}

	reader = bio_reader_create(this->value);

	while (this->record_count)
	{
		if (!reader->read_uint32(reader, &record_id) ||
			!reader->read_uint24(reader, &data_model_pen) ||
			!reader->read_uint8 (reader, &data_model_type) ||
			!reader->read_uint8 (reader, &source_id) ||
			!reader->read_uint8 (reader, &reserved) ||
			!reader->read_data16(reader, &sw_id) ||
			!reader->read_data16(reader, &sw_locator))
		{
			goto end;
		}
		record = chunk_empty;

		if (this->type.type == IETF_ATTR_SW_INVENTORY &&
			!reader->read_data32(reader, &record))
		{
			goto end;
		}
		data_model = pen_type_create(data_model_pen, data_model_type);
		sw_record = swima_record_create(record_id, sw_id, sw_locator);
		sw_record->set_data_model(sw_record, data_model);
		sw_record->set_source_id(sw_record, source_id);
		sw_record->set_record(sw_record, record);
		this->inventory->add(this->inventory, sw_record);
		this->offset += this->value.len - reader->remaining(reader);
		this->value = reader->peek(reader);

		/* at least one software inventory evidence record was processed */
		status = SUCCESS;
		this->record_count--;
	}

	if (this->length == this->offset)
	{
		status = SUCCESS;
	}
	else
	{
		DBG1(DBG_TNC, "inconsistent length for %N/%N", pen_names, PEN_IETF,
					   ietf_attr_names, this->type.type);
		*offset = this->offset;
		status = FAILED;
	}

end:
	reader->destroy(reader);
	return status;
}

METHOD(pa_tnc_attr_t, add_segment, void,
	private_ietf_swima_attr_sw_inv_t *this, chunk_t segment)
{
	this->value = chunk_cat("cc", this->value, segment);
	chunk_free(&this->segment);
	this->segment = this->value;
}

METHOD(pa_tnc_attr_t, get_ref, pa_tnc_attr_t*,
	private_ietf_swima_attr_sw_inv_t *this)
{
	ref_get(&this->ref);
	return &this->public.pa_tnc_attribute;
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_ietf_swima_attr_sw_inv_t *this)
{
	if (ref_put(&this->ref))
	{
		this->inventory->destroy(this->inventory);
		free(this->segment.ptr);
		free(this);
	}
}

METHOD(ietf_swima_attr_sw_inv_t, get_flags, uint8_t,
	private_ietf_swima_attr_sw_inv_t *this)
{
	return this->flags;
}

METHOD(ietf_swima_attr_sw_inv_t, get_request_id, uint32_t,
	private_ietf_swima_attr_sw_inv_t *this)
{
	return this->request_id;
}

METHOD(ietf_swima_attr_sw_inv_t, get_last_eid, uint32_t,
	private_ietf_swima_attr_sw_inv_t *this, uint32_t *eid_epoch)
{
	if (eid_epoch)
	{
		*eid_epoch = this->eid_epoch;
	}
	return this->last_eid;
}

METHOD(ietf_swima_attr_sw_inv_t, get_record_count, uint32_t,
	private_ietf_swima_attr_sw_inv_t *this)
{
	return this->record_count;
}

METHOD(ietf_swima_attr_sw_inv_t, set_inventory, void,
	private_ietf_swima_attr_sw_inv_t *this, swima_inventory_t *inventory)
{
	this->inventory->destroy(this->inventory);
	this->inventory = inventory->get_ref(inventory);
}

METHOD(ietf_swima_attr_sw_inv_t, get_inventory, swima_inventory_t*,
	private_ietf_swima_attr_sw_inv_t *this)
{
	return this->inventory;
}

METHOD(ietf_swima_attr_sw_inv_t, clear_inventory, void,
	private_ietf_swima_attr_sw_inv_t *this)
{
	this->inventory->destroy(this->inventory);
	this->inventory = swima_inventory_create();
}

/**
 * Described in header.
 */
pa_tnc_attr_t *ietf_swima_attr_sw_inv_create(uint8_t flags, uint32_t request_id,
											 uint32_t eid_epoch, uint32_t eid,
											 bool sw_id_only)
{
	private_ietf_swima_attr_sw_inv_t *this;
	ietf_attr_t type;

	type = sw_id_only ? IETF_ATTR_SW_ID_INVENTORY : IETF_ATTR_SW_INVENTORY;

	INIT(this,
		.public = {
			.pa_tnc_attribute = {
				.get_type = _get_type,
				.get_value = _get_value,
				.get_noskip_flag = _get_noskip_flag,
				.set_noskip_flag = _set_noskip_flag,
				.build = _build,
				.process = _process,
				.add_segment = _add_segment,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
			.get_flags = _get_flags,
			.get_request_id = _get_request_id,
			.get_last_eid = _get_last_eid,
			.get_record_count = _get_record_count,
			.set_inventory = _set_inventory,
			.get_inventory = _get_inventory,
			.clear_inventory = _clear_inventory,
		},
		.type = { PEN_IETF, type },
		.flags = flags,
		.request_id = request_id,
		.eid_epoch = eid_epoch,
		.last_eid = eid,
		.inventory = swima_inventory_create(),
		.ref = 1,
	);

	return &this->public.pa_tnc_attribute;
}


/**
 * Described in header.
 */
pa_tnc_attr_t *ietf_swima_attr_sw_inv_create_from_data(size_t length,
										chunk_t data, bool sw_id_only)
{
	private_ietf_swima_attr_sw_inv_t *this;
	ietf_attr_t type;

	type = sw_id_only ? IETF_ATTR_SW_ID_INVENTORY : IETF_ATTR_SW_INVENTORY;

	INIT(this,
		.public = {
			.pa_tnc_attribute = {
				.get_type = _get_type,
				.get_value = _get_value,
				.get_noskip_flag = _get_noskip_flag,
				.set_noskip_flag = _set_noskip_flag,
				.build = _build,
				.process = _process,
				.add_segment = _add_segment,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
			.get_flags = _get_flags,
			.get_request_id = _get_request_id,
			.get_last_eid = _get_last_eid,
			.get_record_count = _get_record_count,
			.set_inventory = _set_inventory,
			.get_inventory = _get_inventory,
			.clear_inventory = _clear_inventory,
		},
		.type = { PEN_IETF, type },
		.length = length,
		.segment = chunk_clone(data),
		.inventory = swima_inventory_create(),
		.ref = 1,
	);

	/* received either complete attribute value or first segment */
	this->value = this->segment;

	return &this->public.pa_tnc_attribute;
}
