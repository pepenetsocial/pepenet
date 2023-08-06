#include "pep.h"
namespace pepenet_social {
ibool pep_args::loadArgsFromJson()
  {
    if (!m_schema_valid)
    {
      return FALSE_IBOOL("Json schema has to be validated before args can be loaded");
    }
    if (!m_json["pep_args"].HasMember("msg"))
    {
      return FALSE_IBOOL("json field msg is required!");
    }
    else
    {
      m_msg = m_json["pep_args"]["msg"].GetString();
    }
    if (m_json["pep_args"].HasMember("pseudonym"))
    {
      m_pseudonym = m_json["pep_args"]["pseudonym"].GetString();
    }
    if (m_json["pep_args"].HasMember("sk_seed"))
    {
      if (!m_json["pep_args"].HasMember("post_pk"))
      {
        m_valid_args = false;
        return FALSE_IBOOL("json field post_pk is required when sk_seed is defined!");
      }
      m_sk_seed = m_json["pep_args"]["sk_seed"].GetString();
    }
    if (m_json["pep_args"].HasMember("post_pk"))
    {
      m_post_pk = m_json["pep_args"]["post_pk"].GetBool();
      if (!m_json["pep_args"].HasMember("sk_seed"))
      {
        m_valid_args = false;
        return FALSE_IBOOL("json field sk_seed is required when post_pk is defined!");
      }
    }
    if (m_json["pep_args"].HasMember("tx_ref"))
    {
      std::string tx_ref_hex = m_json["pep_args"]["tx_ref"].GetString();
      crypto::hash tx_ref_parsed;
      if (!epee::string_tools::hex_to_pod(tx_ref_hex, tx_ref_parsed))
      {
        m_valid_args = false;
        return FALSE_IBOOL("unable to parse tx_ref from json!");
      }
      m_tx_ref = tx_ref_parsed;
    }
    if (m_json["pep_args"].HasMember("pepetag"))
    {
      m_pepetag = m_json["pep_args"]["pepetag"].GetString();
    }
    if (m_json["pep_args"].HasMember("donation_address"))
    {
      m_donation_address = m_json["pep_args"]["donation_address"].GetString();
    }
    
    m_valid_args = true;
    return ibool{ true, INFO_NULLOPT };
  }

void pep_args::setSchema()
{
  m_json_schema_str = R"(
{
  "$id": "pep_args schema pepenet hfv2",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "pepenet pep args",
  "type": "object",
  "properties": {
    "pep_args": {
      "description": "Pep arguments",
      "type": "object",
      "properties": {
        "msg": {
            "type": "string"
        },
        "pseudonym": {
            "type": "string",
            "minLength": 1,
            "maxLength": 32
        },
        "sk_seed": {
            "type": "string"
        },
        "post_pk": {
            "type": "boolean"
        },
        "tx_ref": {
            "type": "string",
            "minLength": 64,
            "maxLength": 64,
            "pattern": "[0-9A-Fa-f]{64}"
        },
        "pepetag": {
            "type": "string",
            "minLength": 1,
            "maxLength": 32
        },
        "donation_address": {
            "type": "string",
            "minLength": 97,
            "maxLength": 108
        }
      },
      "required":[
               "msg"
      ]
    }
  }
}
)";
  m_json_schema_str_loaded = true;
}

  ibool pep::loadFromSocialArgs(pep_args const& args)
  {
    if (!args.m_valid_args)
    {
      return FALSE_IBOOL("invalid social args");
    }
    //copy base fields
    m_msg = args.m_msg;
    m_pseudonym = args.m_pseudonym;
    m_tx_ref = args.m_tx_ref;
    m_pepetag = args.m_pepetag;
    m_donation_address = args.m_donation_address;
    //create pep
    CHECK_AND_ASSERT_RERETURN_IBOOL(dumpBaseToProto()); //base
    if (args.m_sk_seed.has_value()) //create sig
    {
      pepenet_social_protos::pep_base* base_ptr = m_proto.release_base(); //get base prt
      //get keys for signing
      crypto::public_key pk;
      crypto::secret_key sk;
      CHECK_AND_ASSERT_RETURN_IBOOL(pepenet_social::secret_key_from_seed(args.m_sk_seed.value(), sk), "failed to generate sk from sk_seed");
      CHECK_AND_ASSERT_RETURN_IBOOL(crypto::secret_key_to_public_key(sk, pk), "failed to generate pk from sk");
      //add pk to base if requested
      if (args.m_post_pk.value_or(false))
      {
        bytes pk_bytes(pk.data, 32);
        base_ptr->set_pk(pk_bytes);
        m_pk = pk;
      }
      //sign binary base
      bytes base_bytes;
      base_ptr->SerializeToString(&base_bytes);
      m_proto.set_allocated_base(base_ptr); //give base back to proto
      
      crypto::signature sig;
      pepenet_social::sign_msg(base_bytes, sig, pk, sk);
      //convert sig to bytes and set it to proto
      bytes sig_bytes = bytes(sig.c.data, 32) + bytes(sig.r.data, 32);
      //set the sig and pk
      m_proto.set_sig(sig_bytes);
      m_sig = sig;
    }
    m_loaded = true;
    return { true, INFO_NULLOPT };
  }

  ibool pep::dumpBaseToProto()
  {
    pepenet_social_protos::pep_base* base = new pepenet_social_protos::pep_base; //allocate to avoid destructor
    base->set_msg(m_msg);
    if (m_pseudonym.has_value())
    {
      base->set_pseudonym(m_pseudonym.value());
    }
    if (m_pk.has_value())
    {
      bytes pk_bytes;
      CHECK_AND_ASSERT_RETURN_IBOOL(to_bytes(m_pk.value(), pk_bytes), "failed to convert pk to bytes");
      base->set_pk(pk_bytes);
    }
    if (m_tx_ref.has_value())
    {
      base->set_tx_ref(std::string(m_tx_ref.value().data, 32));
    }
    if (m_pepetag.has_value())
    {
      base->set_pepetag(m_pepetag.value());
    }
    if (m_donation_address.has_value())
    {
      base->set_donation_address(m_donation_address.value());
    }
    m_proto.set_allocated_base(base);
    return { true, INFO_NULLOPT };
  }

  ibool pep::dumpToProto()
  {
    dumpBaseToProto();
    if (m_sig.has_value())
    {
      bytes sig_bytes;
      CHECK_AND_ASSERT_RETURN_IBOOL(to_bytes(m_sig.value(), sig_bytes), "failed to convert sig to bytes");
      m_proto.set_sig(sig_bytes);
    }
    m_loaded = true;
    return { true, INFO_NULLOPT };
  }
  
  ibool pep::loadFromProto()
  {
    pepenet_social_protos::pep_base* base_ptr = m_proto.release_base();
    m_msg = base_ptr->msg();
    
    m_pseudonym = get_optional_string(base_ptr->pseudonym());
    
    boost::optional<bytes> parsed_pk_bytes = get_optional_bytes(base_ptr->pk());
    if (parsed_pk_bytes.has_value())
    {
      crypto::public_key pk;
      CHECK_AND_ASSERT_RETURN_IBOOL(from_bytes(pk, parsed_pk_bytes.value()), "invalid pk bytes in proto");
      m_pk = pk;
    }
    boost::optional<bytes> parsed_tx_ref_bytes = get_optional_bytes(base_ptr->tx_ref());
    if (parsed_tx_ref_bytes.has_value())
    {
      crypto::hash parsed_tx_ref;
      CHECK_AND_ASSERT_RETURN_IBOOL(from_bytes(parsed_tx_ref, parsed_tx_ref_bytes.value()), "invalid tx_ref bytes in proto");
      m_tx_ref = parsed_tx_ref;
    }

    m_pepetag = get_optional_string(base_ptr->pepetag());
    m_donation_address = get_optional_string(base_ptr->donation_address());

    m_proto.set_allocated_base(base_ptr); //return base to proto;

    boost::optional<bytes> parsed_sig_bytes = get_optional_bytes(m_proto.sig());
    if (parsed_sig_bytes.has_value())
    {
      crypto::signature parsed_sig;
      CHECK_AND_ASSERT_RETURN_IBOOL(from_bytes(parsed_sig, parsed_sig_bytes.value()), "invalid sig bytes in proto");
      m_sig = parsed_sig;
    }

    m_loaded = true;
    return ibool{ true, INFO_NULLOPT };
  }

  ibool pep::validate()
  {
    if (!m_loaded)
    {
      return FALSE_IBOOL("proto not loaded");
    }
    //verify fields
    std::string compressed_msg;
    bool r = lzma_compress_msg(m_msg, compressed_msg);
    if (m_msg.empty() || compressed_msg.size() > LZMA_PEP_MAX_SIZE)
    {
      return FALSE_IBOOL("invalid msg field");
    }
    if (m_pseudonym.has_value())
    {
      if (m_pseudonym.value().empty() || m_pseudonym.value().size() > PSEUDONYM_MAX_SIZE)
      {
        return FALSE_IBOOL("invalid pseudonym field");
      }
    }
    if (m_pepetag.has_value())
    {
      if (m_pepetag.value().empty() || m_pepetag.value().size() > PEPETAG_MAX_SIZE)
      {
        return FALSE_IBOOL("invalid pepetag field");
      }
    }
    if (m_donation_address.has_value())
    {
      if (m_donation_address.value().empty() || m_donation_address.value().size() > DONATION_ADDRESS_MAX_SIZE)
      {
        return FALSE_IBOOL("invalid donation_address field");
      }
    }
    
    if (m_sig.has_value() && m_pk.has_value()) //verify base
    {
      pepenet_social_protos::pep_base* base_ptr = m_proto.release_base();
      bytes base_bytes;
      if (!base_ptr->SerializeToString(&base_bytes))
      {
        return FALSE_IBOOL("failed to serialize pep base");
      }
      m_proto.set_allocated_base(base_ptr);
      //verify sig
      if (!check_msg_sig(base_bytes, m_sig.value(), m_pk.value()))
      {
        return FALSE_IBOOL("failed to verify pep: invalid sig");
      }
    }
    m_valid = true;
    return ibool{ true, INFO_NULLOPT };
  }

  ibool pep::validate(const boost::optional<crypto::public_key>& pk)
  {
    m_pk = pk;
    ibool r = validate();
    m_pk.reset();
    return r;
  }

}